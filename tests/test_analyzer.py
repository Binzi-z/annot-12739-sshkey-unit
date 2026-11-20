"""分析器端到端测试：召回/误报指标、四类守卫、跨 crate 链路、SARIF、增量一致性。"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(args, cache_dir=None):
    env = dict(os.environ, PYTHONPATH=ROOT)
    cmd = [sys.executable, "-m", "analyzer.cli", "--repo", ROOT] + args
    if cache_dir is not None:
        cmd += ["--incremental", "--cache-dir", cache_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, env=env,
                          encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_recall_and_false_positive_meet_targets():
    doc = _run([])
    labels = json.load(open(os.path.join(ROOT, "labels.json"), encoding="utf-8"))["vulns"]
    truth = {(v["file"], int(v["line"])) for v in labels}
    got = {(f["file"], int(f["line"])) for f in doc["findings"]}
    tp = len(truth & got)
    fp = len(got - truth)
    recall = tp / len(truth)
    fpr = fp / len(got) if got else 0.0
    assert recall >= 0.85, f"召回 {recall:.1%} < 85%"
    assert fpr <= 0.15, f"误报率 {fpr:.1%} > 15%"
    # 22 个 checked decoy 一个都不能报
    assert not any("_checked" in f["chain"][-1]["func"] for f in doc["findings"])


def test_four_sink_classes_and_three_sources_present():
    doc = _run([])
    rules = {f["ruleId"] for f in doc["findings"]}
    assert rules == {"DESER-SESSION-001", "DESER-CACHE-002",
                     "DESER-RPC-003", "DESER-MQ-004"}
    sources = {f["source"] for f in doc["findings"]}
    assert sources == {"queue_message", "network_frame", "file"}


def test_every_finding_has_full_cross_crate_chain_through_trait_object():
    doc = _run([])
    assert doc["findings"]
    for f in doc["findings"]:
        funcs = [hop["func"] for hop in f["chain"]]
        # 必须经 take_one（trait object 擦除点）再到 sink crate
        assert any("take_one" in x for x in funcs), f
        # 链路跨至少 handlers 与一个 sink crate
        crates = {x.split("::")[0] for x in funcs}
        assert "handlers" in crates and len(crates) >= 2, f
        # 每跳都带真实文件与行号
        assert all(hop["file"] and hop["line"] > 0 for hop in f["chain"])


def test_guard_classification_covers_four_kinds():
    sys.path.insert(0, ROOT)
    from analyzer.index import discover
    from analyzer.dataflow import DataflowEngine
    idx = discover(ROOT)
    eng = DataflowEngine(idx)
    expect = {
        "restore_login_checked": "length",
        "load_tenant_checked": "tag",
        "decode_tenant_params_checked": "whitelist",
        "consume_order_event_checked": "hmac",
    }
    for fn_name, kind in expect.items():
        key = next(k for k in idx.funcs if k.endswith(fn_name))
        summary = eng.summarize(key)
        kinds = {g.guard_kind for eff in summary.sink_effects for g in eff.guards}
        assert kind in kinds, (fn_name, kinds)


def test_sarif_contains_codeflows_and_rules():
    env = dict(os.environ, PYTHONPATH=ROOT)
    out = os.path.join(ROOT, ".pytest_cache_sarif.json")
    cmd = [sys.executable, "-m", "analyzer.cli", "--repo", ROOT, "--sarif", out]
    subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, env=env, check=True)
    try:
        doc = json.load(open(out, encoding="utf-8"))
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "bincode-hir-taint-analyzer"
        assert len(run["results"]) == 50
        for res in run["results"]:
            assert res["codeFlows"][0]["threadFlows"][0]["locations"]
            assert res["level"] == "error"
    finally:
        os.remove(out)


def test_incremental_matches_full_and_is_deterministic(tmp_path):
    full = _run([])
    cache = str(tmp_path / "cache")
    first = _run([], cache_dir=cache)
    second = _run([], cache_dir=cache)
    key = lambda d: json.dumps(d["findings"], sort_keys=True, ensure_ascii=False)
    assert key(full) == key(first) == key(second)
