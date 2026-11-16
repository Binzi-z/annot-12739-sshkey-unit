import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import triage  # noqa: E402

EVIDENCE = os.path.join(ROOT, "evidence")


def run(tmp_path):
    out = tmp_path / "timeline.json"
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "triage.py"),
                        EVIDENCE, str(out)],
                       capture_output=True, text=True)
    return r, out


def test_evidence_present():
    for name in ("bash_history.txt", "auth_excerpt.log", "files.txt"):
        assert os.path.exists(os.path.join(EVIDENCE, name))


def test_labels_have_entry_and_persistence():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    assert labels["entry_vector"]
    assert labels["persistence"]


def test_triage_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "hits" in json.loads(out.read_text(encoding="utf-8"))


def test_hits_have_file_and_line(tmp_path):
    _, out = run(tmp_path)
    for h in json.loads(out.read_text(encoding="utf-8"))["hits"]:
        assert h.get("file") and isinstance(h.get("line"), int)


# ---------------------------------------------------------------------------
# Forensic behavior
# ---------------------------------------------------------------------------

def _report():
    return triage.analyze(EVIDENCE)


def test_is_incident_with_systemd_persistence():
    rep = _report()
    assert rep["incident"]["incident"] is True
    assert rep["incident"]["alert"] is True
    assert rep["persistence"]["technique"] == "systemd unit"
    assert rep["entry_vector"] == "stolen ssh key"
    assert rep["account"] == "deploy"


def test_timeline_order_is_key_login_unit_enable():
    rep = _report()
    orders = [s["order"] for s in rep["timeline"]]
    assert orders == sorted(orders)
    titles = [s["event"] for s in rep["timeline"]]
    assert titles == [
        "public key appended to authorized_keys",
        "attacker logs in with the injected key",
        "systemd unit file written",
        "systemd unit enabled (persistence)",
    ]


def test_every_stage_cites_file_and_line():
    rep = _report()
    assert rep["timeline"]
    for stage in rep["timeline"]:
        assert stage["evidence"], stage["event"]
        for c in stage["evidence"]:
            assert c["file"].startswith("evidence/") or "/" in c["file"]
            assert isinstance(c["line"], int) and c["line"] > 0
            assert c["snippet"]


def test_key_ingress_is_written_on_site_with_physical_evidence():
    rep = _report()
    ki = rep["key_ingress"]
    assert ki["verdict"] == "written_on_site"
    cites = {(c["file"], c["line"]) for c in ki["supporting_evidence"]}
    # the echo >> authorized_keys command and its epoch marker
    assert ("evidence/bash_history.txt", 52) in cites
    # independent syslog confirmation of the modification
    assert ("evidence/auth_excerpt.log", 26) in cites
    # the external login proving the key works
    assert ("evidence/auth_excerpt.log", 27) in cites
    # no evidence of copying an existing key or fetching one remotely
    assert ki["reuse_of_existing_key_evidence"] == "none found"
    assert ki["remote_fetch_evidence"] == "none found"


def test_noise_commands_are_suppressed():
    rep = _report()
    flagged = {(h["file"], h["line"]) for h in rep["hits"]}
    # everyday ops from bash_history must never appear as hits
    for benign_line in (2, 4, 16, 26, 28, 44):  # cd/ls/git pull/systemctl status
        assert ("evidence/bash_history.txt", benign_line) not in flagged
    # and internal ops logins must not be treated as attacker logins
    assert ("evidence/auth_excerpt.log", 1) not in flagged
    # the noise is still accounted for, with a reason, for auditability
    suppressed = {(n["file"], n["line"]) for n in rep["benign_noise_suppressed"]}
    assert ("evidence/bash_history.txt", 2) in suppressed


def test_external_login_is_flagged_internal_is_not():
    rep = _report()
    login_stage = next(s for s in rep["timeline"] if s["order"] == 2)
    ext = [o for o in login_stage["observations"] if o.get("external")]
    assert len(ext) == 1
    assert ext[0]["ip"] == "198.51.100.23"
    assert ext[0]["account"] == "deploy"


def test_timestamp_dependencies_are_declared():
    rep = _report()
    deps = rep["timestamp_dependencies"]
    assert any("cross-source" in d for d in deps)
    assert any("NOT timestamp-dependent" in d for d in deps)
    # skew is actually measured, not asserted
    corr = rep["clock_correlation"]
    assert corr["best_fit_offset"] == "UTC+8"
    gaps = {g["assumed_offset"]: g["bash_minus_syslog_minutes"]
            for g in corr["cross_source_gap_minutes"]}
    assert gaps["UTC+9"] == 2
    assert gaps["UTC+8"] == -58


def test_benign_key_rotation_is_not_an_alert(tmp_path):
    # Synthetic fixture: authorized_keys appended, but no external login and
    # no persistence. This is normal key rotation and must not be reported.
    d = tmp_path / "rot"
    d.mkdir()
    (d / "bash_history.txt").write_text(
        "#1790825640\n"
        "echo ssh-ed25519 AAAA... >> ~/.ssh/authorized_keys\n"
        "#1790825700\n"
        "ls -la\n",
        encoding="utf-8")
    (d / "auth_excerpt.log").write_text(
        "Oct 01 12:32:00 web01 authorized_keys modified\n"
        "Oct 01 12:40:00 web01 sshd[1]: Accepted publickey for ops "
        "from 10.0.0.5 port 22 ssh2\n",
        encoding="utf-8")
    rep = triage.analyze(str(d))
    assert rep["incident"]["incident"] is False
    assert rep["incident"]["alert"] is False
    assert "rotation" in rep["incident"]["classification"]


def test_rotation_becomes_incident_when_chained(tmp_path):
    d = tmp_path / "attack"
    d.mkdir()
    (d / "bash_history.txt").write_text(
        "#1790825640\n"
        "echo ssh-rsa AAAA... >> ~/.ssh/authorized_keys\n"
        "#1790825683\n"
        "vim /etc/systemd/system/x.service\n"
        "#1790825753\n"
        "systemctl enable x\n",
        encoding="utf-8")
    (d / "auth_excerpt.log").write_text(
        "Oct 01 12:33:00 web01 Accepted publickey for deploy "
        "from 198.51.100.23 port 1 ssh2\n",
        encoding="utf-8")
    rep = triage.analyze(str(d))
    assert rep["incident"]["incident"] is True
    assert [s["order"] for s in rep["timeline"]] == [1, 2, 3, 4]


def test_out_of_scope_artifacts_recorded_but_not_alerted():
    rep = _report()
    paths = {a["path"] for a in rep["out_of_scope_artifacts"]["artifacts"]}
    assert "/var/www/html/uploads/shell.php" in paths
    assert "/var/spool/cron/crontabs/deploy" in paths
    # they must not leak into the incident hits
    hit_files = {h["file"] for h in rep["hits"]}
    assert "evidence/files.txt" not in hit_files
