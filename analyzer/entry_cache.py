"""入口实例化效应缓存：按入口函数 body 哈希缓存其源实例化后的 SinkEffect 列表。

noop 增量时入口 body 未变、且其依赖的函数摘要未变，可直接复用，连入口文件的
tree-sitter 解析与逐语句 walk 都跳过。效应里的 Origin/Guard 均为可 JSON 化纯数据。
"""
from __future__ import annotations

import json
import os

from .dataflow import effect_from_dict, effect_to_dict

ENTRY_SCHEMA_VERSION = "entry-effect-v1"


class EntryEffectCache:
    def __init__(self, path: str):
        self.path = path
        self.doc: dict = {"version": ENTRY_SCHEMA_VERSION, "entries": {}}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                if doc.get("version") == ENTRY_SCHEMA_VERSION:
                    self.doc = doc
            except (json.JSONDecodeError, OSError):
                pass

    def load(self) -> dict:
        """返回 {entry_key: (body_hash, [SinkEffect, ...])}。"""
        out = {}
        for key, rec in self.doc["entries"].items():
            out[key] = (rec["body_hash"],
                        [effect_from_dict(d) for d in rec.get("effects", [])])
        return out

    def save(self, entry_map: dict) -> None:
        payload = {}
        for key, (body_hash, effects) in entry_map.items():
            payload[key] = {"body_hash": body_hash,
                            "effects": [effect_to_dict(e) for e in effects]}
        self.doc["entries"] = payload
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(self.doc, fh, ensure_ascii=False, sort_keys=True)
