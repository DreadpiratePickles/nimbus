import json
import subprocess
import sys
from pathlib import Path

from nimbus.checks import __main__ as cli

PY_ROOT = Path(__file__).resolve().parents[2]


def test_cli_list(capsys):
    assert cli.main(["--provider", "aws", "--list"]) == 0
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) >= 50
    assert any(l.startswith("iam_root_mfa_enabled\t") for l in lines)


def test_cli_list_filters(capsys):
    assert cli.main(["--list", "--compliance", "cis_aws:1.4"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and out[0].startswith("iam_no_root_access_key")
    assert cli.main(["--list", "--services", "s3", "--severity", "critical"]) == 0
    ids = {l.split("\t")[0] for l in capsys.readouterr().out.strip().splitlines()}
    assert ids == {"s3_bucket_public_access", "s3_bucket_policy_public_write_access"}


def test_cli_module_subprocess_list():
    proc = subprocess.run([sys.executable, "-m", "nimbus.checks", "--list", "--checks", "kms_cmk_rotation_enabled"],
                          cwd=PY_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("kms_cmk_rotation_enabled\t")


def test_cli_run_json_and_jsonl(ctx, tmp_path, monkeypatch, capsys):
    import nimbus.checks.context as context_mod

    monkeypatch.setattr(context_mod.AuditContext, "_build_session", lambda self: ctx.session)
    ctx.client("s3").create_bucket(Bucket="cli-bucket")
    out = tmp_path / "findings.json"
    assert cli.main(["--regions", "us-east-1", "--services", "s3", "--output", str(out)]) == 0
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data
    assert all(f["source"] == "nimbus" and f["check_id"].startswith("s3_") for f in data)
    assert cli.main(["--regions", "us-east-1", "--checks", "s3_bucket_object_versioning", "--jsonl"]) == 0
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert lines and all(l["check_id"] == "s3_bucket_object_versioning" for l in lines)
