#!/usr/bin/env python3
"""baseline：正则版 bincode 反序列化扫描器（改进前起点）。

不做 HIR、不做数据流、不看调用链：一行里出现 bincode::deserialize 就报。
因此带长度校验/类型白名单/HMAC 的 checked 版本也会中招，这正是本题要改进的误报来源。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "rust", "crates")
SINK_RE = re.compile(r"bincode::(?:deserialize|deserialize_from)\s*\(")


def scan() -> list[dict]:
    findings = []
    for dirpath, dirnames, names in os.walk(SRC):
        dirnames.sort()
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            with open(path, encoding="utf-8") as fh:
                for no, line in enumerate(fh, 1):
                    if SINK_RE.search(line):
                        findings.append({
                            "file": rel,
                            "line": no,
                            "ruleId": "DESER-BINCODE-001",
                            "message": line.strip()[:200],
                        })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings


def to_sarif(findings: list[dict]) -> dict:
    results = []
    for f in findings:
        results.append({
            "ruleId": "DESER-BINCODE-001",
            "level": "error",
            "message": {"text": "未校验的 bincode 反序列化候选点：" + f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"], "startColumn": 1},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bincode-regex-baseline",
                "rules": [{
                    "id": "DESER-BINCODE-001",
                    "name": "bincode-deserialization",
                    "shortDescription": {"text": "bincode 反序列化落点"},
                    "defaultConfiguration": {"level": "error"},
                }],
            }},
            "results": results,
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="regex bincode baseline")
    ap.add_argument("--sarif", metavar="PATH")
    args = ap.parse_args()
    findings = scan()
    if args.sarif:
        text = json.dumps(to_sarif(findings), ensure_ascii=False, indent=2) + "\n"
        if args.sarif == "-":
            sys.stdout.write(text)
        else:
            with open(args.sarif, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
    else:
        json.dump({"findings": findings}, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
