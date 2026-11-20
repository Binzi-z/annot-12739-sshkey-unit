"""阶段三：入口实例化、源绑定、链路重建与告警判定。

入口 = 形参类型末段名命中 MessageSource/FrameSource/FileSource 的函数。
对每个入口，把该形参槽绑定为具体源 Origin，跑一次摘要实例化（复用阶段二缓存，
入口本身只做一次轻量 walk），得到带完整 call_chain 与守卫状态的落点。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .dataflow import GUARD_KIND_HINT, DataflowEngine
from .hir import Origin
from .index import CrateIndex

SINK_LABEL = {
    "session": "会话反序列化",
    "cache": "缓存反序列化",
    "rpc": "RPC 参数解码",
    "mq": "消息队列消费",
}
MISSING_HINT = {
    "session": "长度上限校验 MAX_SESSION_BYTES",
    "cache": "长度上限 MAX_CACHE_BYTES 或类型 tag CACHE_TAG 校验",
    "rpc": "长度上限 MAX_RPC_BYTES 或类型白名单 ALLOWED_RPC_TYPES",
    "mq": "签名/HMAC 校验（verify_signature）或消息长度、事件类型校验",
    "bincode": "长度上限校验（raw.len() <= 上限）或类型白名单 / tag 校验",
}
SINK_LABEL = {
    "session": "会话反序列化",
    "cache": "缓存反序列化",
    "rpc": "RPC 参数解码",
    "mq": "消息队列消费",
    "bincode": "bincode 反序列化",
}


@dataclass
class Finding:
    rule_id: str
    sink_kind: str
    source: str
    entry: str
    entry_file: str
    entry_line: int
    sink_file: str
    sink_line: int
    chain: list[tuple[str, str, int]]      # (函数 key, 文件, 行)
    guards: list[dict]
    missing: str
    key: str = ""

    def __post_init__(self):
        self.key = f"{self.sink_file}:{self.sink_line}|{self.entry}"


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    sanitized: list[dict] = field(default_factory=list)   # 被守卫正确净化的落点（覆盖率证据）
    entries: list[dict] = field(default_factory=list)
    reused_summaries: int = 0
    changed_files: list[str] = field(default_factory=list)


def analyze(idx: CrateIndex, cache=None, unchanged_files: set[str] | None = None
            ) -> tuple[AnalysisResult, "DataflowEngine"]:
    eng = DataflowEngine(idx)
    result = AnalysisResult()

    if cache is not None:
        # 增量：未变文件的过程内摘要以惰性 dict 保留，按需物化，避免 noop 时全量反序列化
        if unchanged_files is None:
            unchanged_files = cache.unchanged_files(idx.file_hash)
        unchanged = unchanged_files
        blobs = {k: blob for f in unchanged
                 for k, blob in cache.summary_blob(f).items()
                 if k in idx.funcs}
        idx._lazy_summary_blobs = blobs
        # 重解析文件集由 CLI 依据反向闭包显式传入（reparsed_files）；缺省退回全集差集
        reparsed = getattr(idx, "reparsed_files", None)
        changed_files = set(reparsed) if reparsed is not None else (
            set(idx.file_crate) - unchanged)
        if changed_files:
            from .dataflow import reverse_closure
            eng.changed_keys = reverse_closure(idx, changed_files, blobs)
        # 仅预物化脏闭包内函数（数量少）；未变函数在 summarize 时惰性命中
        for key in (eng.changed_keys or set()):
            if key in blobs:
                from .dataflow import _built_from_blob
                eng._cache[key] = _built_from_blob(blobs[key])
        result.reused_summaries = len(blobs)
        result.changed_files = sorted(changed_files)
        # 脏闭包内的入口，其缓存的实例化效应可能因 callee 摘要变化而过期，强制重算
        idx.dirty_entry_keys = eng.changed_keys

    # 预计算函数摘要（跨 crate 复用）。增量模式下未变函数走惰性 blob，不在此预物化，
    # 只有变更闭包内（或全量模式）的函数才真正计算。
    lazy_blobs = getattr(idx, "_lazy_summary_blobs", None)
    for key in idx.funcs:
        if lazy_blobs is not None and key in lazy_blobs and key not in (eng.changed_keys or set()):
            continue
        eng.summarize(key)

    entries = _detect_entries(idx)
    result.entries = entries
    seen: set[str] = set()
    entry_cache = getattr(idx, "entry_effect_cache", None)   # dict[key] -> (body_hash, effects)
    dirty_entries = getattr(idx, "dirty_entry_keys", None)   # 增量闭包判定为脏的入口

    for ent in entries:
        key = ent["key"]
        src_kind = ent["source"]
        fn = idx.funcs[key]

        # 入口效应缓存：body 未变且不在脏闭包内，直接复用上次实例化的 effects（连 CST 都不碰）
        cached_eff = None
        if entry_cache is not None and (dirty_entries is None or key not in dirty_entries):
            rec = entry_cache.get(key)
            if rec and rec[0] == fn.summary.body_hash:
                cached_eff = rec[1]

        if cached_eff is not None:
            effects = cached_eff
        else:
            source_origin = Origin(kind="source", name=src_kind)
            env = {name: (frozenset([source_origin]) if i == ent["param_index"]
                          else frozenset([Origin(kind="param", index=i)]))
                   for i, name in enumerate(fn.summary.params)}
            types = {name: fn.summary.param_types[i] for i, name in enumerate(fn.summary.params)}
            effects, _rets = _run_entry(eng, key, env, types)
            if entry_cache is not None:
                entry_cache[key] = (fn.summary.body_hash, effects)

        for eff in effects:
            # 只有喂给 bincode 的字节确实来自该源才算链路成立
            source_hops = ()
            for o in eff.arg_origins:
                if o.kind == "source" and o.name == src_kind:
                    source_hops = o.hops
                    break
            else:
                continue
            guard_kinds = {g.guard_kind for g in eff.guards}
            chain = _rebuild_chain(idx, eff.call_chain, key, eff.callee_key, eff.line,
                                   source_hops, fn.summary.file)
            if guard_kinds:
                result.sanitized.append({
                    "sink_file": idx.funcs[eff.callee_key].summary.file
                    if eff.callee_key in idx.funcs else key,
                    "sink_line": eff.line, "entry": key, "source": src_kind,
                    "guards": sorted(guard_kinds),
                })
                continue
            sink_file = idx.funcs[eff.callee_key].summary.file
            fk = f"{key}|{sink_file}:{eff.line}"
            if fk in seen:
                continue
            seen.add(fk)
            result.findings.append(Finding(
                rule_id=eff.sink_rule, sink_kind=eff.sink_kind, source=src_kind,
                entry=key, entry_file=fn.summary.file, entry_line=fn.summary.start_line,
                sink_file=sink_file, sink_line=eff.line, chain=chain,
                guards=[], missing=MISSING_HINT[eff.sink_kind],
            ))
    result.findings.sort(key=lambda f: (f.sink_file, f.sink_line, f.entry))
    return result, eng


# ---------------------------------------------------------------- 入口识别

def _load_summaries_parallel(eng, blobs: dict) -> int:
    """把缓存 blob 反序列化成 BuiltSummary。

    实测 Windows spawn 下多进程序列化 4 万对象的开销超过并行收益，保持串行；
    真正的大头（入口 walk）已由 EntryEffectCache 消除。
    """
    from .dataflow import _built_from_blob
    for key, blob in blobs.items():
        eng._cache[key] = _built_from_blob(blob)
    return len(blobs)


def _detect_entries(idx: CrateIndex) -> list[dict]:
    out = []
    for key, fn in idx.funcs.items():
        for i, ty in enumerate(fn.summary.param_types):
            if ty in idx.source_types:
                out.append({
                    "key": key, "source": _source_kind(ty),
                    "param_index": i, "param_type": ty,
                    "file": fn.summary.file, "line": fn.summary.start_line,
                })
    out.sort(key=lambda e: (e["file"], e["line"], e["key"]))
    return out


def _source_kind(type_name: str) -> str:
    """源类型名 -> 语义源类别；命中不了具体类别的按队列消息保守归类。"""
    low = type_name.lower()
    if "frame" in low or "wire" in low or "socket" in low or "tcp" in low:
        return "network_frame"
    if "file" in low or "disk" in low or "path" in low:
        return "file"
    return "queue_message"


# ---------------------------------------------------------------- 入口 walk

def _run_entry(eng: DataflowEngine, key: str, env: dict, types: dict):
    """复用 summarize 的遍历器，但以源实例化后的初始环境跑入口函数。

    增量模式下未变入口文件走骨架（node=None），此处按需对该文件解析一次并缓存节点，
    避免在索引阶段整体重解析巨型入口文件。
    """
    from .hir import first_of_type
    from .index import PARSER
    fn = eng.idx.funcs[key]
    if fn.node is None and fn.summary.file in eng.idx.files:
        _ensure_cst(eng, fn.summary.file)
        fn = eng.idx.funcs[key]
    effects, calls, rets = [], [], set()
    block = first_of_type(fn.node, "block")
    eng._walk_block(key, block, fn.src, dict(env), dict(types), frozenset(), (key,),
                    effects, calls, rets)
    return effects, rets


def _ensure_cst(eng: DataflowEngine, rel: str) -> None:
    """对一个骨架文件惰性补 CST，并就地把该文件内函数的 node/src 填充。"""
    from .index import PARSER, _find_all
    idx = eng.idx
    raw = idx.files.get(rel)
    if raw is None:
        return
    root = PARSER.parse(raw).root_node
    # 收集该文件内的函数 key，解析后按出现顺序回填节点
    from .hir import text as _text, first_of_type as _first
    keys = [k for k, f in idx.funcs.items() if f.summary.file == rel]
    nodes = {_text(raw, _first(fnode, "identifier")): fnode
             for fnode in _find_all(root, "function_item")}
    for k in keys:
        f = idx.funcs[k]
        fnode = nodes.get(f.summary.name)
        if fnode is not None:
            f.node = fnode
            f.src = raw


# ---------------------------------------------------------------- 链路重建

def _rebuild_chain(idx: CrateIndex, call_chain: tuple, entry_key: str,
                   sink_owner: str, sink_line: int, source_hops: tuple,
                   entry_file: str) -> list[tuple[str, str, int]]:
    """完整数据流通路：入口函数 -> Origin 携带的每个跨函数中转（如 take_one）-> 落点。

    hops 里的行号是「调用点」行（落在调用者文件中），最后一跳用 sink 真实行覆盖。
    """
    chain: list[tuple[str, str, int]] = [(entry_key, entry_file,
                                          idx.funcs[entry_key].summary.start_line)]
    for fn_key, call_line in source_hops:
        node = idx.funcs.get(fn_key)
        if node is None:
            continue
        chain.append((fn_key, node.summary.file, call_line))
    # 终点：实际持有 bincode 的函数 + 落点真实行
    sink_node = idx.funcs.get(sink_owner)
    if sink_node is not None:
        chain.append((sink_owner, sink_node.summary.file, sink_line))
    return chain
