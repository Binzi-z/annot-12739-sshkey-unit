"""SARIF 2.1.0 与 JSON 报告。

每条告警带：
  - 落点主位置（bincode::deserialize 真实行）；
  - codeFlows.threadFlow：源入口 -> trait object 取帧 -> 跨 crate sink -> 落点的完整路径；
  - message：源类型、四类落点名称、本可插入的长度校验/白名单位置。
不写时间戳，保证增量与全量输出字节级可比对。
"""
from __future__ import annotations

import json

from .dataflow import GUARD_KIND_HINT
from .driver import AnalysisResult, Finding, SINK_LABEL

RULES = {
    "DESER-SESSION-001": ("bincode-session", "会话反序列化",
                          "会话字节未经长度校验/类型白名单直接 bincode 反序列化。"),
    "DESER-CACHE-002": ("bincode-cache", "缓存反序列化",
                        "缓存中的字节直接反序列化成结构体，未做长度或 tag 校验。"),
    "DESER-RPC-003": ("bincode-rpc", "RPC 参数解码",
                      "RPC 参数解码直接用 bincode，参数类型未走白名单。"),
    "DESER-MQ-004": ("bincode-mq", "消息队列消费",
                     "队列消息 payload 直接反序列化，未校验消息长度与事件类型。"),
}
SOURCE_CN = {
    "queue_message": "队列消息（mq::MessageSource）",
    "network_frame": "网络帧（wire::FrameSource，长度前缀拆帧后 payload）",
    "file": "文件（ingest::FileSource，std::fs::read 读出的字节）",
}


def _message(f: Finding) -> str:
    steps = " -> ".join(k.split("::")[-1] for k, _file, _line in f.chain)
    return (
        f"[{SINK_LABEL[f.sink_kind]}] 源「{SOURCE_CN[f.source]}」的未校验字节经 {steps} "
        f"直达 bincode::deserialize（{f.sink_file}:{f.sink_line}）。"
        f"中间本可在进入反序列化前插入：{f.missing}。"
    )


def to_sarif(result: AnalysisResult) -> dict:
    rules = []
    for rid, (name, short, help_text) in RULES.items():
        rules.append({
            "id": rid, "name": name,
            "shortDescription": {"text": short},
            "fullDescription": {"text": help_text},
            "defaultConfiguration": {"level": "error"},
            "help": {"text": help_text},
        })
    sarif_results = []
    for f in result.findings:
        thread_locations = []
        # 路径第一步：源入口函数
        for k, file, line in f.chain:
            thread_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file},
                        "region": {"startLine": line},
                    },
                    "message": {"text": f"调用步骤：{k}"},
                },
                "nestingLevel": len(thread_locations),
            })
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": "error",
            "message": {"text": _message(f)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.sink_file},
                    "region": {"startLine": f.sink_line, "startColumn": 1},
                },
                "message": {"text": f"落点：bincode::deserialize（{SINK_LABEL[f.sink_kind]}）"},
            }],
            "codeFlows": [{
                "threadFlows": [{"locations": thread_locations}],
            }],
            "properties": {
                "source": f.source,
                "entry": f.entry,
                "entryFile": f.entry_file,
                "missingGuard": f.missing,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bincode-hir-taint-analyzer",
                "version": "1.0.0",
                "informationUri": "https://example.invalid/bincode-hir-taint-analyzer",
                "rules": rules,
            }},
            "results": sarif_results,
            "properties": {
                "entriesScanned": len(result.entries),
                "sanitizedSinks": len(result.sanitized),
            },
        }],
    }


def to_json(result: AnalysisResult) -> dict:
    findings = [{
        "file": f.sink_file,
        "line": f.sink_line,
        "ruleId": f.rule_id,
        "source": f.source,
        "entry": f.entry,
        "entry_file": f.entry_file,
        "entry_line": f.entry_line,
        "sink_kind": f.sink_kind,
        "chain": [{"func": k, "file": fp, "line": ln} for k, fp, ln in f.chain],
        "missing_guard": f.missing,
        "message": _message(f),
    } for f in result.findings]
    return {"findings": findings, "sanitized": result.sanitized,
            "entries": result.entries}


def dump(result: AnalysisResult, path: str | None, sarif: bool) -> str:
    doc = to_sarif(result) if sarif else to_json(result)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    if path and path != "-":
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return text
