"""解析层增量缓存：未变文件复用其函数 HIR 骨架，连 tree-sitter 解析都跳过。

与 dataflow 的摘要缓存分层：
  - ParseCache 保存「文件 -> 函数骨架（形参/类型/行号/方法归属/源类型）」，
    使增量运行只对变更文件调 tree-sitter；
  - IncrementalCache 保存「函数 -> 过程内数据流摘要」，跳过未变函数的数据流重算。
两层都以内容哈希 + schema 版本为键，且最终告警由同一条入口实例化逻辑产出，
因此增量与全量天然走同一套 HIR/摘要，结果一致。
"""
from __future__ import annotations

import json
import os

PARSE_SCHEMA_VERSION = "parse-hir-v1"


class ParseCache:
    def __init__(self, path: str):
        self.path = path
        self.doc: dict = {"version": PARSE_SCHEMA_VERSION, "files": {}}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                if doc.get("version") == PARSE_SCHEMA_VERSION:
                    self.doc = doc
            except (json.JSONDecodeError, OSError):
                pass

    def get(self, file: str, file_hash: str):
        rec = self.doc["files"].get(file)
        if rec and rec.get("hash") == file_hash:
            return rec
        return None

    def has(self, file: str, mtime: float, size: int) -> bool:
        """快速命中：不读文件内容，仅凭 mtime+size 判断骨架是否可复用。"""
        rec = self.doc["files"].get(file)
        return bool(rec and rec.get("mtime") == mtime and rec.get("size") == size)

    def put(self, file: str, file_hash: str, payload: dict,
            mtime: float = 0.0, size: int = 0) -> None:
        self.doc["files"][file] = {"hash": file_hash, "mtime": mtime,
                                   "size": size, **payload}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(self.doc, fh, ensure_ascii=False, sort_keys=True)
