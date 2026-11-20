"""增量缓存：文件级内容哈希 -> 函数摘要缓存。

一致性口径（题面要求增量与全量一致）：
  - 键 = 文件 blake2b 哈希 + 分析器分析模式版本号；文件未变则直接反序列化复用该文件内
    函数的 BuiltSummary（过程内、上下文不敏感的摘要，与调用上下文无关，可安全复用）；
  - 文件变了，只重算该文件以及通过调用边反向可达的函数闭包；
  - 入口实例化每次都跑（它本来就是 O(入口数 × 浅调用链)），因此增量结果与全量走的是
    同一套摘要、同一条数据流路径，不存在两套逻辑。
"""
from __future__ import annotations

import json
import os

ANALYSIS_SCHEMA_VERSION = "hir-v2"


class IncrementalCache:
    def __init__(self, cache_path: str):
        self.path = cache_path
        self.doc: dict = {"version": ANALYSIS_SCHEMA_VERSION, "files": {}}
        if os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                if doc.get("version") == ANALYSIS_SCHEMA_VERSION:
                    self.doc = doc
            except (json.JSONDecodeError, OSError):
                pass

    def unchanged_files(self, file_hash: dict[str, str]) -> set[str]:
        cached = self.doc["files"]
        return {f for f, h in file_hash.items() if cached.get(f, {}).get("hash") == h}

    def summary_blob(self, file: str) -> dict:
        return self.doc["files"].get(file, {}).get("summaries", {})

    def update(self, file_hash: dict[str, str], summaries: dict[str, dict]) -> None:
        for f, h in file_hash.items():
            self.doc["files"][f] = {"hash": h, "summaries": summaries.get(f, {})}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(self.doc, fh, ensure_ascii=False, indent=1, sort_keys=True)
