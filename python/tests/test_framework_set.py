"""`nimbus report --framework-set default|all|<names>` (parity with Go's internal/cli/report.go)."""
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nimbus.cli import app
from nimbus.compliance import DEFAULT_FRAMEWORK_SET, framework_set, load_frameworks

runner = CliRunner()
_GO_REPORT = Path(__file__).resolve().parents[2] / "internal" / "cli" / "report.go"


def test_default_set_matches_go():
    m = re.search(r"var defaultFrameworkSet = \[\]string\{([^}]*)\}", _GO_REPORT.read_text())
    assert m, "defaultFrameworkSet not found in internal/cli/report.go"
    assert list(DEFAULT_FRAMEWORK_SET) == re.findall(r'"([^"]+)"', m.group(1))


def test_framework_set_resolution():
    all_ = load_frameworks()
    want = ["cis_aws", "cis_k8s", "nist_800_53", "pci_dss", "soc2", "hipaa", "iso_27001", "gdpr"]
    assert framework_set("default", ["aws", "kubernetes", "iac", "aws"]) == want
    assert framework_set(None, []) == want[2:]
    assert framework_set("all", []) == sorted(all_) and len(all_) > 100
    assert framework_set("soc2, pci,c5_aws,soc2", ["aws"]) == ["soc2", "pci_dss", "c5_aws"]
    assert framework_set("cis", ["azure", "iac"]) == ["cis_azure"]
    with pytest.raises(ValueError, match="nope_framework"):
        framework_set("soc2,nope_framework", [])


def test_report_all_uses_default_set(seeded, tmp_path):
    db = ["--db", seeded.path]
    m = len(load_frameworks())
    r = runner.invoke(app, ["report", "--framework", "all", "--format", "json", *db])
    assert r.exit_code == 0, r.output
    note = f"of {m} frameworks (framework-set default); use --framework-set all for every framework"
    assert note in r.output
    keys = [x["framework"]["key"] for x in json.loads(r.stdout)]
    assert keys == framework_set("default", [f.provider for f in seeded.findings()])
    assert "c5_aws" not in keys and "soc2" in keys

    r = runner.invoke(app, ["report", "--framework", "all", "--framework-set", "soc2,pci", "--format", "json", *db])
    assert r.exit_code == 0, r.output
    assert [x["framework"]["key"] for x in json.loads(r.stdout)] == ["soc2", "pci_dss"]
    assert f"2 of {m} frameworks (framework-set soc2,pci)" in r.output and "use --framework-set all" not in r.output

    r = runner.invoke(app, ["report", "--framework-set", "all", "--format", "json", *db])
    assert r.exit_code == 0 and len(json.loads(r.stdout)) == m

    assert runner.invoke(app, ["report", "--framework-set", "nope_framework", *db]).exit_code == 2
    assert runner.invoke(app, ["report", "--framework", "soc2", "--framework-set", "all", *db]).exit_code == 2
