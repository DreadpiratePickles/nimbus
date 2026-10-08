import json

from typer.testing import CliRunner

from nimbus.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and r.output.startswith("nimbus ")


def test_ask_query_report_risk(seeded, tmp_path):
    db = ["--db", seeded.path]
    r = runner.invoke(app, ["ask", "public buckets", "--json", *db])
    assert r.exit_code == 0 and json.loads(r.output)["intent"] == "public_buckets"
    r = runner.invoke(app, ["query", "--list"])
    assert "top_risky_accounts" in r.output
    r = runner.invoke(app, ["query", "--named", "top_risky_accounts", "-o", "json", *db])
    assert json.loads(r.output)[0]["account"] == "111111111111"
    r = runner.invoke(app, ["query", "DELETE FROM findings", *db])
    assert r.exit_code == 1
    out = tmp_path / "soc2.html"
    r = runner.invoke(app, ["report", "--framework", "soc2", "--format", "html", "--out", str(out), *db])
    assert r.exit_code == 0 and "%" in out.read_text()
    r = runner.invoke(app, ["report", "--framework", "all", "--out", str(tmp_path / "exec.html"), *db])
    assert r.exit_code == 0 and "SOC 2" in (tmp_path / "exec.html").read_text()
    custom = tmp_path / "c.yaml"
    custom.write_text("name: Mini\ncontrols:\n  M-1:\n    title: t\n    weaknesses: [NO_MFA]\n")
    r = runner.invoke(app, ["report", "--framework", "x", "--format", "md", "--custom", str(custom), *db])
    assert r.exit_code == 0 and "| M-1 | t | FAIL |" in r.output
    r = runner.invoke(app, ["risk", "--top", "2", "--json", *db])
    assert len(json.loads(r.output)) == 2


def test_explain_investigate_policy_fix_plugin(seeded, tmp_path):
    db = ["--db", seeded.path]
    fid = seeded.findings(canonical_id="EC2_IMDSV1")[0].id
    assert runner.invoke(app, ["explain", fid, *db]).output.startswith("An attacker could")
    assert "IMDSv1" in runner.invoke(app, ["explain", "ap-admin", *db]).output
    r = runner.invoke(app, ["investigate", fid, *db])
    assert r.exit_code == 0 and "Sensitive resources reachable" in r.output
    r = runner.invoke(app, ["policy", "deny privileged pods"])
    assert "package nimbus.k8s.privileged_pod" in r.output
    r = runner.invoke(app, ["fix", fid, "--format", "terraform", *db])
    assert "http_tokens" in r.output
    r = runner.invoke(app, ["guidance", "EC2_IMDSV1", *db])
    assert "cloud-posture fix --finding EC2_IMDSV1" in r.output
    r = runner.invoke(app, ["frameworks"])
    assert "soc2" in r.output
    plug = tmp_path / "p.py"
    plug.write_text("import nimbus\n@nimbus.plugin.check('p1','t','HIGH','aws')\ndef c():\n    return [{'resource_id':'r1','account':'1'}]\n")
    r = runner.invoke(app, ["plugin", "run", str(plug), "--jsonl"])
    assert r.exit_code == 0 and json.loads(r.output.strip())["check_id"] == "p1"
    r = runner.invoke(app, ["ingest", str(tmp_path / "missing.json"), *db])
    assert r.exit_code != 0
