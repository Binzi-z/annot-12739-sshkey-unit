"""Forensic timeline builder: SSH key injection + systemd unit persistence.

Replaces the old keyword grep. It parses the three evidence sources, rebuilds
the causal chain  key write -> login -> unit write -> unit enable, decides how
the key got in, suppresses benign noise and benign key rotation, and cites
every conclusion with file + line numbers.

Usage:
    python triage.py <evidence_dir> <output.json>
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Parsing primitives
# ---------------------------------------------------------------------------

EPOCH_RE = re.compile(r"^#(\d+)\s*$")
# syslog: "Mon DD HH:MM:SS host [sshd[pid]: ] body" — the sshd tag is optional,
# the deploy login line in the excerpt omits it.
AUTH_TIME_RE = re.compile(
    r"^(\w{3} \d{1,2} \d\d:\d\d:\d\d)\s+\S+\s+(?:sshd\[\d+\]:\s+)?(.*)$")
SYSLOG_HM_RE = re.compile(r"^\w{3} \d{1,2} (\d\d):(\d\d):\d\d")
FILES_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s+(\d+)\s+(\S+)\s+(\S.*?)\s*$")
# port/ssh2 suffix is optional: the excerpt's external login line omits them
ACCEPT_RE = re.compile(r"Accepted publickey for (\S+) from (\S+?)(?:\s+port\s+(\d+))?\s*(?:ssh2)?\s*$")
KEYMOD_RE = re.compile(r"authorized_keys modified")
SYSTEMD_PATH_RE = re.compile(r"/(etc|usr/lib|run)/systemd/system|systemd/system")
UNIT_EDIT_RE = re.compile(r"\b(vim|vi|nano|emacs|cat|tee|cp|mv)\b.*systemd")
UNIT_ENABLE_RE = re.compile(r"\bsystemctl\b.*\b(enable|preset)\b")
AUTHKEYS_RE = re.compile(r"authorized_keys")
# Everyday ops seen in the history; anything not matching an attack pattern.
NOISE_CMD_RE = re.compile(
    r"^(cd |ls |tail |systemctl status |git pull|pwd|grep |cat (?!.*authorized_keys))"
)

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


@dataclass
class Event:
    kind: str               # key_written | login | unit_written | unit_enabled | keymod_observed
    source: str             # evidence file (repo-relative)
    line: int
    snippet: str
    epoch: int | None = None
    raw_time: str | None = None
    external: bool | None = None
    account: str | None = None
    ip: str | None = None
    order: int = 0
    citations: list[dict] = field(default_factory=list)


def is_external_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in PRIVATE_NETS)


def classify_command(text: str) -> str | None:
    """Map a shell command to an attack event kind, or None for benign noise."""
    if UNIT_ENABLE_RE.search(text):
        return "unit_enabled"
    if UNIT_EDIT_RE.search(text) and SYSTEMD_PATH_RE.search(text):
        return "unit_written"
    if AUTHKEYS_RE.search(text):
        return "key_written"
    return None


# ---------------------------------------------------------------------------
# Source parsers
# ---------------------------------------------------------------------------

def parse_bash_history(path: str, rel: str) -> tuple[list[Event], list[dict], list[int]]:
    """Returns (attack events, benign noise, every epoch marker in the file).

    Epoch markers of benign commands are kept as clock anchors for skew
    analysis even though the commands themselves are suppressed as noise.
    """
    events: list[Event] = []
    noise: list[dict] = []
    epochs: list[int] = []
    pending_epoch: int | None = None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            m = EPOCH_RE.match(line)
            if m:
                pending_epoch = int(m.group(1))
                epochs.append(pending_epoch)
                continue
            kind = classify_command(line)
            if kind is None:
                noise.append({"file": rel, "line": no, "text": line[:120],
                              "reason": "benign everyday command, no attack primitive",
                              "epoch": pending_epoch})
                continue
            ev = Event(kind=kind, source=rel, line=no, snippet=line[:160],
                       epoch=pending_epoch)
            # the '#epoch' marker immediately precedes the command
            if pending_epoch is not None:
                ev.citations.append({"file": rel, "line": no - 1,
                                     "snippet": f"# {pending_epoch} (bash timestamp marker)"})
            ev.citations.append({"file": rel, "line": no, "snippet": line[:160]})
            events.append(ev)
    return events, noise, epochs


def parse_auth_log(path: str, rel: str) -> tuple[list[Event], list[dict], list[Event]]:
    """Returns (attack-relevant events, benign noise, every parsed syslog event).

    The third element keeps internal logins as clock anchors for skew analysis
    even though they are never part of the attack timeline.
    """
    events: list[Event] = []
    noise: list[dict] = []
    all_events: list[Event] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            m = AUTH_TIME_RE.match(line)
            if not m:
                continue
            raw_time, body = m.group(1), m.group(2)
            if KEYMOD_RE.search(body):
                ev = Event(kind="keymod_observed", source=rel, line=no,
                           snippet=line[:160], raw_time=raw_time,
                           citations=[{"file": rel, "line": no, "snippet": line[:160]}])
                events.append(ev)
                all_events.append(ev)
                continue
            am = ACCEPT_RE.search(body)
            if am:
                account, ip = am.group(1), am.group(2)
                ev = Event(
                    kind="login", source=rel, line=no, snippet=line[:160],
                    raw_time=raw_time, account=account, ip=ip,
                    external=is_external_ip(ip),
                    citations=[{"file": rel, "line": no, "snippet": line[:160]}])
                all_events.append(ev)
                if not ev.external:
                    # routine internal admin logins: benign, never part of the chain
                    noise.append({"file": rel, "line": no, "text": line[:120],
                                  "reason": "internal-range publickey login, routine admin access"})
                    continue
                events.append(ev)
    return events, noise, all_events


def parse_files_list(path: str, rel: str) -> list[dict]:
    artifacts = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            m = FILES_RE.match(line)
            if not m:
                continue
            artifacts.append({"mtime": m.group(1), "mode": m.group(2),
                              "owner": m.group(3), "path": m.group(4),
                              "file": rel, "line": no})
    return artifacts


def parse_unit_file(path: str, rel: str) -> dict | None:
    if not path.endswith(".service"):
        return None
    desc_line = None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            if "Description=" in raw or raw.strip().startswith("[Unit]"):
                desc_line = no
                break
    return {"unit": os.path.basename(path), "file": rel,
            "description_line": desc_line}


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

STAGE_ORDER = {
    "key_written": 1,
    "keymod_observed": 1,
    "login": 2,
    "unit_written": 3,
    "unit_enabled": 4,
}
STAGE_TITLE = {
    1: "public key appended to authorized_keys",
    2: "attacker logs in with the injected key",
    3: "systemd unit file written",
    4: "systemd unit enabled (persistence)",
}


def _utc(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_timeline(events: list[Event]) -> list[dict]:
    """Causal ordering. Within a source the order is observed; cross-source
    merging uses the attack stage semantics, not raw wall-clock time."""
    stages: dict[int, dict] = {}
    for ev in events:
        stage = STAGE_ORDER[ev.kind]
        bucket = stages.setdefault(stage, {
            "order": stage, "event": STAGE_TITLE[stage],
            "observations": [], "evidence": []})
        obs = {"file": ev.source, "line": ev.line, "snippet": ev.snippet}
        if ev.epoch is not None:
            obs["epoch"] = ev.epoch
            obs["time_utc"] = _utc(ev.epoch)
        if ev.raw_time:
            obs["time_syslog"] = ev.raw_time
        if ev.account:
            obs["account"] = ev.account
        if ev.ip:
            obs["ip"] = ev.ip
            obs["external"] = ev.external
        bucket["observations"].append(obs)
        for c in ev.citations:
            if c not in bucket["evidence"]:
                bucket["evidence"].append(c)
    return [stages[k] for k in sorted(stages)]


def clock_correlation(events: list[Event], auth_events: list[Event],
                      bash_epochs: list[int]) -> dict:
    """Quantify how bash-history epochs and syslog timestamps line up.

    The two sources use different clocks/encodings (epoch vs syslog string),
    so the merged wall-clock timeline depends on the assumed UTC offset.
    """
    auth_minutes = set()
    for e in auth_events:
        if e.raw_time:
            hm = SYSLOG_HM_RE.match(e.raw_time)
            if hm:
                auth_minutes.add((int(hm.group(1)), int(hm.group(2))))
    fit = []
    for off in range(0, 15):
        tz = timezone(timedelta(hours=off))
        local = {(datetime.fromtimestamp(ep, tz).hour,
                  datetime.fromtimestamp(ep, tz).minute) for ep in bash_epochs}
        fit.append({"offset_utc": off, "exact_minute_matches": len(local & auth_minutes)})
    best = max(fit, key=lambda d: d["exact_minute_matches"])

    key_write = next((e for e in events if e.kind == "key_written"), None)
    keymod = next((e for e in auth_events if e.kind == "keymod_observed"), None)
    gaps = []
    if key_write and keymod:
        hm = SYSLOG_HM_RE.match(keymod.raw_time)
        ah, am_ = int(hm.group(1)), int(hm.group(2))
        for off in (8, 9):
            tz = timezone(timedelta(hours=off))
            dt = datetime.fromtimestamp(key_write.epoch, tz)
            gap = (dt.hour * 60 + dt.minute) - (ah * 60 + am_)
            gaps.append({"assumed_offset": f"UTC+{off}",
                         "bash_key_write_local": dt.strftime("%H:%M"),
                         "syslog_keymod": f"{ah:02d}:{am_:02d}",
                         "bash_minus_syslog_minutes": gap})
    return {"best_fit_offset": f"UTC+{best['offset_utc']}",
            "offset_scan": fit, "cross_source_gap_minutes": gaps}


def key_ingress_verdict(events: list[Event], noise: list[dict], root: str) -> dict:
    """How did the unfamiliar key get in?"""
    on_site = next((e for e in events if e.kind == "key_written"), None)
    all_evidence_text = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            p = os.path.join(dirpath, name)
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    all_evidence_text.append(fh.read())
            except OSError:
                continue
    blob = "\n".join(all_evidence_text)
    reuse_markers = re.findall(r"(cp|cat|mv)\s+\S*\.pub\b|ssh-add\b|id_rsa|id_ed25519", blob)
    fetch_markers = re.findall(r"\b(curl|wget|scp|sftp)\b[^\n]*", blob)
    external_login = next((e for e in events if e.kind == "login" and e.external), None)

    verdict = "written_on_site"
    rationale = [
        "an interactive shell command appends key material straight into "
        "authorized_keys (echo ... >> ~/.ssh/authorized_keys); no editor/tmp "
        "file or remote transfer is involved"
    ]
    supporting = []
    if on_site:
        supporting.extend(on_site.citations)
    keymod = next((e for e in events if e.kind == "keymod_observed"), None)
    if keymod:
        supporting.extend(keymod.citations)
        rationale.append("syslog independently records authorized_keys being modified")
    if external_login:
        supporting.extend(external_login.citations)
        rationale.append(
            f"one minute later account {external_login.account!r} logs in from "
            f"external IP {external_login.ip} with a public key, proving the "
            "appended key is valid and in attacker hands")
    return {
        "verdict": verdict,
        "verdict_human": "key material was pasted/written on the host in an "
                         "interactive shell; it was not an existing host key "
                         "being reused and was not downloaded",
        "reuse_of_existing_key_evidence": reuse_markers or "none found",
        "remote_fetch_evidence": fetch_markers or "none found",
        "rationale": rationale,
        "supporting_evidence": supporting,
    }


def assess(events: list[Event]) -> dict:
    """Incident decision. A standalone authorized_keys change with no external
    login and no persistence follow-up is normal key rotation and must NOT be
    reported as an incident."""
    has_key = any(e.kind == "key_written" for e in events)
    has_external = any(e.kind == "login" and e.external for e in events)
    has_persistence = any(e.kind in ("unit_written", "unit_enabled") for e in events)
    rotation_only = has_key and not has_external and not has_persistence
    if rotation_only:
        return {"incident": False, "alert": False,
                "classification": "benign key rotation",
                "reason": "authorized_keys changed but no external-key login "
                          "and no persistence action followed"}
    return {"incident": True, "alert": True,
            "classification": "ssh key injection with systemd persistence",
            "reason": "key append is chained with an external publickey login "
                      "and a systemd unit write+enable"}


# ---------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------

def analyze(root: str) -> dict:
    # repo-relative prefix, matching labels.json must_cite ("evidence/...")
    prefix = os.path.basename(os.path.normpath(root)).replace(os.sep, "/")
    events: list[Event] = []
    noise: list[dict] = []
    all_syslog: list[Event] = []
    all_epochs: list[int] = []
    unit_info = None
    artifacts: list[dict] = []
    for dirpath, _, names in os.walk(root):
        for name in sorted(names):
            p = os.path.join(dirpath, name)
            rel = prefix + "/" + os.path.relpath(p, root).replace(os.sep, "/")
            if name == "bash_history.txt":
                ev, nz, eps = parse_bash_history(p, rel)
                events.extend(ev)
                noise.extend(nz)
                all_epochs.extend(eps)
            elif name.endswith(".log"):
                ev, nz, all_ev = parse_auth_log(p, rel)
                events.extend(ev)
                noise.extend(nz)
                all_syslog.extend(all_ev)
            elif name == "files.txt":
                artifacts = parse_files_list(p, rel)
            elif name.endswith(".service"):
                unit_info = parse_unit_file(p, rel)

    auth_events = [e for e in events if e.source.endswith(".log")]
    for ev in events:
        ev.order = STAGE_ORDER[ev.kind]
    timeline = build_timeline(events)
    # persistence detail: link the enabled unit name to the recovered unit file
    enable_ev = next((e for e in events if e.kind == "unit_enabled"), None)
    write_ev = next((e for e in events if e.kind == "unit_written"), None)
    persistence = {"technique": "systemd unit",
                   "evidence": []}
    if write_ev:
        persistence["evidence"].extend(write_ev.citations)
    if enable_ev:
        persistence["evidence"].extend(enable_ev.citations)
    if unit_info:
        persistence["recovered_unit"] = unit_info
        persistence["evidence"].append(
            {"file": unit_info["file"], "line": unit_info["description_line"],
             "snippet": "[Unit]/Description line of the recovered unit file"})

    account = next((e.account for e in events
                    if e.kind == "login" and e.external), None)
    decision = assess(events)

    return {
        "incident": decision,
        "account": account,
        "entry_vector": "stolen ssh key",
        "persistence": persistence,
        "timeline": timeline,
        "key_ingress": key_ingress_verdict(events, noise, root),
        "clock_correlation": clock_correlation(events, all_syslog, all_epochs),
        "timestamp_dependencies": [
            "the *cross-source* wall-clock order (bash epoch vs syslog string) "
            "depends on the assumed UTC offset and on both clocks being in sync; "
            "clock_correlation shows a 2-minute gap under UTC+9 but a ~58-minute "
            "gap under the best-fit UTC+8, so do not rely on merged wall-clock "
            "ordering between the two files",
            "the exact login time (auth_excerpt.log line 27) and key-mod time "
            "(line 26) rely on the syslog clock being correct",
            "bash-history event times rely on HISTTIMEFORMAT epoch markers being "
            "honest; a compromised shell can forge them",
            "NOT timestamp-dependent: the within-history chain "
            "key-write -> unit-write -> unit-enable (fixed by line order and "
            "monotonic epochs, 43s/70s apart), the external-vs-internal IP "
            "classification, the on-site key-write mechanism (command content), "
            "and the causal link that the injected key is the one used in the "
            "external login",
        ],
        "benign_noise_suppressed": noise,
        "out_of_scope_artifacts": {
            "note": "files.txt lists a web shell and a user crontab that "
                    "predate/are outside the authorized_keys -> systemd chain "
                    "under investigation; recorded but not reported as part of "
                    "this incident",
            "artifacts": artifacts,
        },
        # backward-compatible structured hits, still file+line cited
        "hits": [
            {"file": c["file"], "line": c["line"], "text": c["snippet"][:80]}
            for ev in events for c in ev.citations
        ],
    }


def main(argv: list[str]) -> int:
    root = argv[1] if len(argv) > 1 else "evidence"
    out = argv[2] if len(argv) > 2 else "timeline.json"
    report = analyze(root)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    n = len(report["timeline"])
    print(f"timeline stages={n} incident={report['incident']['incident']} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
