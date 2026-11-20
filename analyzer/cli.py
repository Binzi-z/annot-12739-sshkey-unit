#!/usr/bin/env python3
"""CLI：全量 / 增量扫描，输出 SARIF 或 eval.py 兼容的 JSON。

全量：tree-sitter 多进程并行解析 + 一次性数据流。
增量：未变文件跳过解析（ParseCache 骨架）与数据流（摘要缓存），只重算变更闭包。

用法：
  python -m analyzer.cli --repo .                          # 全量 JSON
  python -m analyzer.cli --repo . --sarif out.sarif        # 全量 SARIF
  python -m analyzer.cli --repo . --incremental --cache-dir .cache
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .cache import IncrementalCache
from .driver import analyze
from .entry_cache import EntryEffectCache
from .index import discover, discover_parallel, skeleton_of
from .parse_cache import ParseCache
from .report import dump


def _list_files_partial(repo: str, need_cst: set[str], parse_cache, unchanged: set[str],
                        skeleton: dict, walk_files: set[str]):
    """增量索引：need_cst 文件读内容并解析，其余未变文件从骨架缓存重建（不读内容、不解析）。"""
    from .index import _list_files, discover
    # need_cst 与 walk_files 需要源码；其余未变文件完全不读内容
    idx = _list_files(repo, only=need_cst | walk_files)
    for f in unchanged:
        rec = parse_cache.doc["files"].get(f)
        if rec and f not in skeleton:
            skeleton[f] = rec
    idx2 = discover(repo, changed=need_cst, skeleton=skeleton)
    idx2.crates = {**idx.crates, **idx2.crates}
    idx2.lazy_cst_files = walk_files
    return idx2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HIR-based bincode taint analyzer")
    ap.add_argument("--repo", default=".", help="仓库根目录（含 rust/crates）")
    ap.add_argument("--sarif", metavar="PATH", help="输出 SARIF 2.1.0；缺省输出 JSON")
    ap.add_argument("--incremental", action="store_true", help="启用两层增量缓存")
    ap.add_argument("--cache-dir", default=".cache")
    ap.add_argument("--workers", type=int, default=0, help="全量并行解析进程数")
    ap.add_argument("--stats", action="store_true", help="stderr 打印耗时与缓存命中")
    args = ap.parse_args()

    t0 = time.perf_counter()
    inc_cache = df_cache = parse_cache = None
    skeleton: dict[str, dict] = {}
    changed: set[str] | None = None
    unchanged: set[str] = set()
    all_files: list = []

    if args.incremental:
        os.makedirs(args.cache_dir, exist_ok=True)
        parse_cache = ParseCache(os.path.join(args.cache_dir, "parse.json"))
        df_cache = IncrementalCache(os.path.join(args.cache_dir, "dataflow.json"))
        entry_cache = EntryEffectCache(os.path.join(args.cache_dir, "entry.json"))

        # 第一步：只 stat 不读内容，凭 mtime+size 快速判定未变文件
        from .index import list_rust_files, stat_of
        all_files = list_rust_files(args.repo)
        unchanged, changed = set(), set()
        for rel, _crate, abs_path in all_files:
            if parse_cache.has(rel, *stat_of(abs_path)):
                unchanged.add(rel)
            else:
                changed.add(rel)
        # 入口文件不强制重解析：未变入口走骨架，其源实例化效应优先命中 entry 缓存，
        # 只有效应缺失/失效时才惰性解析该入口文件的 CST。
        entry_files = {rel for rel, _c, _p in all_files
                       if os.path.basename(rel) in {"queue.rs", "frame.rs", "file.rs"}
                       or "handler" in rel}

        # 用缓存摘要里的 CallRec（纯数据，不碰 CST）预计算反向调用闭包，
        # 把受变更影响的函数所在文件纳入重解析，保证它们重算时有真实 CST。
        from .dataflow import reverse_closure
        cached_blobs = {k: blob for f in unchanged
                        for k, blob in df_cache.summary_blob(f).items()}
        # 先建一个仅含骨架的轻量索引，供闭包解析函数->文件归属
        skel_idx = discover(args.repo, changed=set(),
                            skeleton={f: parse_cache.doc["files"][f] for f in unchanged
                                      if f in parse_cache.doc["files"]})
        affected_keys = reverse_closure(skel_idx, changed, cached_blobs)
        affected_files = {skel_idx.funcs[k].summary.file for k in affected_keys
                          if k in skel_idx.funcs}
        need_cst = changed | affected_files
        walk_files = entry_files & unchanged
        for f in (unchanged & need_cst) | walk_files:
            rec = parse_cache.doc["files"].get(f)
            if rec and f not in skeleton:
                skeleton[f] = rec

        idx = _list_files_partial(args.repo, need_cst, parse_cache, unchanged,
                                  skeleton, walk_files)
        idx.entry_effect_cache = entry_cache.load()
        idx.reparsed_files = need_cst
    else:
        entry_cache = None
        idx = (discover_parallel(args.repo, args.workers) if args.workers != 1
               else discover(args.repo))
    t_parse = time.perf_counter()

    result, eng = analyze(idx, cache=df_cache, unchanged_files=unchanged)
    t_analyze = time.perf_counter()

    if args.incremental:
        # 回填变更文件骨架并落盘（带 mtime/size 供下次 stat 快判）；摘要缓存全量更新
        fresh = skeleton_of(idx)
        stat_map = {rel: stat_of(abs_path) for rel, _c, abs_path in all_files}
        for f in changed:
            payload = {"funcs": {k: v for k, v in fresh["funcs"].items() if v["file"] == f},
                       "source_types": fresh["source_types"]}
            mt, sz = stat_map.get(f, (0.0, 0))
            parse_cache.put(f, idx.file_hash.get(f, ""), payload, mtime=mt, size=sz)
        parse_cache.save()
        file_of = {k: fn.summary.file for k, fn in idx.funcs.items()}
        new_blobs = eng.dump_summaries(file_of)
        # 未变文件沿用缓存里的旧摘要 blob，变更文件用本次重算结果覆盖
        merged: dict[str, dict] = {}
        for f in unchanged:
            old = df_cache.summary_blob(f)
            if old:
                merged[f] = old
        for f, blob in new_blobs.items():
            merged[f] = blob
        # 哈希只为全量模式的兼容键；增量模式下驱动以 unchanged_files 为准
        hash_for_update = {f: parse_cache.doc["files"].get(f, {}).get("hash", "")
                           for f in idx.file_crate}
        df_cache.update(hash_for_update, merged)
        df_cache.save()
        if hasattr(idx, "entry_effect_cache"):
            entry_cache.save(idx.entry_effect_cache)

    text = dump(result, args.sarif, sarif=bool(args.sarif))
    if not args.sarif or args.sarif == "-":
        sys.stdout.write(text)
    if args.stats:
        print(
            f"files={len(idx.files)} funcs={len(idx.funcs)} findings={len(result.findings)} "
            f"sanitized={len(result.sanitized)} parse={t_parse - t0:.3f}s "
            f"analyze={t_analyze - t_parse:.3f}s total={time.perf_counter() - t0:.3f}s "
            f"reused_summaries={result.reused_summaries} "
            f"reparsed_files={len(changed) if changed is not None else len(idx.files)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
