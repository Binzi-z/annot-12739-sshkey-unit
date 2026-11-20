"""语料自检：labels 行号 anchor、4 类 sink、3 类源、baseline 召回/误报。"""
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINK_RE = re.compile(r"bincode::(?:deserialize|deserialize_from)\s*\(")


def labels():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)["vulns"]


def lines_of(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read().splitlines()


def run_baseline():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "baseline", "scan.py")],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    return json.loads(proc.stdout)["findings"]


def test_fifty_labels_point_at_real_bincode_lines():
    vs = labels()
    assert len(vs) == 50, "题面要求 50 条标注样本，实际 %d" % len(vs)
    for v in vs:
        assert v["sink"] in {"session_deserialization", "cache_deserialization",
                             "rpc_param_decode", "mq_consume"}
        ls = lines_of(v["file"])
        assert 1 <= int(v["line"]) <= len(ls), "%s:%s 越界" % (v["file"], v["line"])
        line = ls[int(v["line"]) - 1]
        assert SINK_RE.search(line), "%s:%s 不是 bincode sink：%s" % (v["file"], v["line"], line)


def test_four_sink_classes_and_three_sources():
    vs = labels()
    sinks, sources = {}, {}
    for v in vs:
        sinks[v["sink"]] = sinks.get(v["sink"], 0) + 1
        sources[v["source"]] = sources.get(v["source"], 0) + 1
    for k in ("session_deserialization", "cache_deserialization", "rpc_param_decode", "mq_consume"):
        assert sinks.get(k, 0) >= 10, "sink %s 只有 %d 条" % (k, sinks.get(k, 0))
    for k in ("queue_message", "network_frame", "file"):
        assert sources.get(k, 0) >= 10, "source %s 只有 %d 条" % (k, sources.get(k, 0))


def test_baseline_recall_and_false_positive_room():
    truth = {(v["file"], int(v["line"])) for v in labels()}
    got = {(f["file"], int(f["line"])) for f in run_baseline()}
    tp = len(truth & got)
    recall = tp / len(truth) if truth else 0.0
    fp_rate = (len(got - truth) / len(got)) if got else 0.0
    assert recall >= 0.90, "baseline 召回 %.1f%% < 90%%" % (recall * 100)
    assert fp_rate > 0.20, "baseline 误报率 %.1f%% <= 20%%，题目没有改进空间" % (fp_rate * 100)


def test_cross_crate_layout():
    assert os.path.exists(os.path.join(ROOT, "rust", "Cargo.toml"))
    crates = os.listdir(os.path.join(ROOT, "rust", "crates"))
    for c in ("ingest", "wire", "mq", "session", "cache", "rpc", "consumer", "handlers"):
        assert c in crates, "缺 crate %s" % c
    rs = []
    for dirpath, _, names in os.walk(os.path.join(ROOT, "rust", "crates")):
        rs += [n for n in names if n.endswith(".rs")]
    assert len(rs) >= 15, "Rust 源文件只有 %d 个" % len(rs)


def test_prompt_matches_topic_file():
    topic = r"D:\AI-zhongqiang\cc-codex-annotation\topics\12739.txt"
    if not os.path.exists(topic):
        pytest.skip("topic file not present")
    raw = open(topic, encoding="utf-8").read()
    for ch in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        raw = raw.replace(ch, "")
    with open(os.path.join(ROOT, "prompt.txt"), encoding="utf-8") as fh:
        assert fh.read().strip() == raw.strip()
