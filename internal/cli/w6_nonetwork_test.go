package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// W6-POLISH item 5 (r4 #14 / N7): under --no-network / CLOUD_POSTURE_NO_NETWORK=1, `onboard` and
// `doctor` make no network call. Every outbound HTTP(S) connection of the child process goes to a
// dead proxy that only counts connections; the control run (network allowed) proves the proxy
// is honoured, so "0 connections" means something.
func TestOnboardAndDoctorMakeNoNetworkCallUnderNoNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var hits int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&hits, 1)
			c.Close() // dead proxy
		}
	}()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o755)
	cfg := filepath.Join(dir, "cloud-posture.yaml")
	os.WriteFile(cfg, []byte("accounts:\n  prod:\n    provider: aws\n    regions: [us-east-1]\n"), 0o644)
	proxy := "http://" + ln.Addr().String()
	env := []string{"HOME=" + home, "HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "https_proxy=" + proxy, "http_proxy=" + proxy,
		"NO_PROXY=", "no_proxy=", "AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE", "AWS_SECRET_ACCESS_KEY=fake", "AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_MAX_ATTEMPTS=1", "GITHUB_TOKEN=ghp_fake", "PATH=", "CLOUD_POSTURE_PYTHON=/nonexistent/python",
		"CLOUD_POSTURE_DB=" + filepath.Join(dir, "p.db")}

	start := time.Now()
	out, _ := runSelfExit(t, dir, append(env, "CLOUD_POSTURE_NO_NETWORK=1"), "doctor", "-c", cfg)
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("doctor under CLOUD_POSTURE_NO_NETWORK=1 made %d connection(s):\n%s", n, out)
	}
	if !strings.Contains(out, "skipped (no-network)") || !strings.Contains(out, "credentials aws/prod") {
		t.Errorf("doctor must say the identity check was skipped (no-network):\n%s", out)
	}
	out, _ = runSelfExit(t, dir, append(env, "CLOUD_POSTURE_NO_NETWORK=1"), "onboard", "--yes", "--out", filepath.Join(dir, "onboarded.yaml"))
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("onboard under CLOUD_POSTURE_NO_NETWORK=1 made %d connection(s):\n%s", n, out)
	}
	if !strings.Contains(out, "skipped (no-network)") {
		t.Errorf("onboard must say detection was skipped (no-network):\n%s", out)
	}
	out, _ = runSelfExit(t, dir, env, "--no-network", "onboard", "--yes", "--aws", "--out", filepath.Join(dir, "onboarded.yaml"))
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("onboard --no-network made %d connection(s):\n%s", n, out)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("no-network runs took %s (something waited on the network)", time.Since(start))
	}

	// Control: with the network allowed the same doctor reaches the (dead) proxy.
	// (TestMain sets CLOUD_POSTURE_NO_NETWORK=1 in every child; the helper below clears it.)
	cmd := exec.Command(os.Args[0], "-test.run=^TestW6HelperNetworkAllowed$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append(env, "NIMBUS_W6_NET_ARGS=doctor\x1f-c\x1f"+cfg)...)
	b, _ := cmd.CombinedOutput()
	out = string(b)
	if atomic.LoadInt64(&hits) == 0 {
		t.Fatalf("control failed: doctor never used the proxy, so the zero counts above prove nothing:\n%s", out)
	}
}

// TestW6HelperNetworkAllowed is not a real test: the control run above uses it to run the CLI
// with the network allowed (TestMain forces CLOUD_POSTURE_NO_NETWORK=1).
func TestW6HelperNetworkAllowed(t *testing.T) {
	a := os.Getenv("NIMBUS_W6_NET_ARGS")
	if a == "" {
		t.Skip("helper")
	}
	os.Unsetenv("CLOUD_POSTURE_NO_NETWORK")
	root.SetArgs(strings.Split(a, "\x1f"))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
