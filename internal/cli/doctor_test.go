package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func fakeDoctorEnv(identityErr map[string]error, tools map[string]string, netErr error) doctorEnv {
	return doctorEnv{
		identity: func(_ context.Context, a *config.Account) (string, error) {
			if err := identityErr[a.Provider]; err != nil {
				return "", err
			}
			return "id-for-" + a.Name, nil
		},
		lookPath: func(name string) (string, error) {
			if v, ok := tools[name]; ok {
				return "/usr/local/bin/" + name + " " + v, nil
			}
			return "", errors.New("not found")
		},
		version: func(_ context.Context, path string) (string, error) {
			return path[strings.LastIndex(path, " ")+1:], nil
		},
		python:   func(*config.Config) string { return "/usr/bin/python3" },
		httpHead: func(_ context.Context, url string) error { return netErr },
		feeds:    []string{"https://example.invalid/kev.json"},
	}
}

func writeDoctorConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "cloud-posture.yaml")
	cfg := "accounts:\n  prod:\n    provider: aws\n    profile: prod\n  dev:\n    provider: azure\n    subscription_id: 00000000-0000-0000-0000-000000000000\n"
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDoctorReportsAndFailsOnBrokenCredentials(t *testing.T) {
	dir := t.TempDir()
	flagConfig = writeDoctorConfig(t, dir)
	flagDB = filepath.Join(dir, "missing.db")
	t.Cleanup(func() { flagConfig, flagDB = "", "" })
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "") // TestMain sets it; this test exercises the feed probe
	env := fakeDoctorEnv(map[string]error{"azure": errors.New("Please run 'az login'")}, map[string]string{"prowler": "5.1.0", "trivy": "0.55.0"}, errors.New("dial tcp: no route"))
	var buf bytes.Buffer
	err := runDoctor(context.Background(), env, &buf)
	out := buf.String()
	if err == nil {
		t.Fatalf("doctor must exit non-zero when a check fails:\n%s", out)
	}
	for _, want := range []string{
		"ok", "credentials aws/prod", "id-for-prod",
		"fail", "credentials azure/dev", "az login",
		"tool prowler", "5.1.0", "tool checkov", "warn",
		"python layer", "database", "no database yet",
		"config", "intel feed", "no route",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
	if _, statErr := os.Stat(flagDB); !os.IsNotExist(statErr) {
		t.Errorf("doctor must not create a database")
	}
}

func TestDoctorPassesWhenHealthy(t *testing.T) {
	dir := t.TempDir()
	flagConfig = writeDoctorConfig(t, dir)
	flagDB = filepath.Join(dir, "p.db")
	t.Cleanup(func() { flagConfig, flagDB = "", "" })
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	env := fakeDoctorEnv(nil, map[string]string{"prowler": "5", "checkov": "3", "trivy": "0.55", "steampipe": "1"}, nil)
	var buf bytes.Buffer
	if err := runDoctor(context.Background(), env, &buf); err != nil {
		t.Fatalf("healthy doctor failed: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "schema v") {
		t.Errorf("doctor must report the schema version:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "FAIL") || strings.Contains(buf.String(), " fail ") {
		t.Errorf("unexpected failure row:\n%s", buf.String())
	}
}

// V2 defect 12: doctor honours --no-network / CLOUD_POSTURE_NO_NETWORK and does not
// probe the KEV/EPSS feeds.
func TestDoctorSkipsFeedsWithNoNetwork(t *testing.T) {
	dir := t.TempDir()
	flagConfig = writeDoctorConfig(t, dir)
	flagDB = filepath.Join(dir, "missing.db")
	t.Cleanup(func() { flagConfig, flagDB, flagNoNetwork = "", "", false })
	for _, viaEnv := range []bool{false, true} {
		flagNoNetwork = !viaEnv
		t.Setenv("CLOUD_POSTURE_NO_NETWORK", map[bool]string{false: "", true: "1"}[viaEnv])
		env := fakeDoctorEnv(nil, nil, nil)
		probed := 0
		env.httpHead = func(context.Context, string) error { probed++; return nil }
		var buf bytes.Buffer
		runDoctor(context.Background(), env, &buf)
		if probed != 0 {
			t.Fatalf("viaEnv=%v: doctor sent %d feed request(s) under no-network", viaEnv, probed)
		}
		if !strings.Contains(buf.String(), "skipped (no-network)") {
			t.Fatalf("viaEnv=%v: feed check must say skipped (no-network):\n%s", viaEnv, buf.String())
		}
	}
}
