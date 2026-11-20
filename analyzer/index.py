"""阶段一：语法解析 + HIR 索引。

用 tree-sitter 解析每个 .rs 文件，自建：
  1. crate / 模块路径解析（不依赖 cargo，不依赖编译器）；
  2. 函数符号表（全限定 key -> FnSummary 骨架 + CST 节点）；
  3. 调用边与类型末段名索引，供阶段二的数据流和跨 crate 解析使用。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from tree_sitter import Language, Node, Parser

import tree_sitter_rust

from .hir import (
    FnSummary,
    children_of_type,
    first_of_type,
    hash_block,
    is_dyn,
    text,
    type_last_name,
)

PARSER = Parser(Language(tree_sitter_rust.language()))


def _read_file(item):
    rel, abs_path = item
    raw = open(abs_path, "rb").read()
    import hashlib
    return rel, raw, hashlib.blake2b(raw, digest_size=16).hexdigest()


@dataclass
class FnNode:
    summary: FnSummary
    node: Node
    src: bytes


@dataclass
class CrateIndex:
    root: str
    crates: dict[str, str] = field(default_factory=dict)          # crate 名 -> src 目录
    files: dict[str, bytes] = field(default_factory=dict)         # 相对路径 -> 源码
    file_crate: dict[str, str] = field(default_factory=dict)      # 相对路径 -> crate 名
    funcs: dict[str, FnNode] = field(default_factory=dict)        # 全限定 key -> FnNode
    by_name: dict[str, list[str]] = field(default_factory=dict)   # 末段函数名 -> keys
    by_method: dict[str, list[str]] = field(default_factory=dict) # 方法名 -> keys
    file_hash: dict[str, str] = field(default_factory=dict)       # 相对路径 -> 内容哈希
    source_types: set[str] = field(default_factory=set)           # impl ByteSource 的具体类型
    method_owners: dict[str, dict[str, str]] = field(default_factory=dict)
    # method_owners[方法名][impl 所有者类型] = 函数 key，用于类型化方法解析

    # ---- 跨 crate 名称解析 -------------------------------------------------

    def resolve_method(self, method: str, owner_type: str = "") -> list[str]:
        if owner_type and method in self.method_owners:
            exact = self.method_owners[method].get(owner_type)
            if exact:
                return [exact]
        return list(self.by_method.get(method, ()))

    def resolve_fn(self, path: str) -> list[str]:
        # SessionStore::default / take_one 这类路径，先按末段名查
        tail = path.split("::")[-1]
        if tail in self.by_name:
            return list(self.by_name[tail])
        return list(self.by_method.get(tail, ()))


def _module_path(rel_parts: list[str]) -> str:
    """src/foo/bar.rs -> foo::bar；src/lib.rs -> （crate 根，空串）。"""
    parts = list(rel_parts)
    last = parts[-1][:-3]  # 去 .rs
    parts[-1] = last
    if parts == ["lib"] or parts == ["mod"]:
        return ""
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(p for p in parts if p)


def list_rust_files(repo_root: str) -> list[tuple[str, str, str]]:
    """只枚举 .rs 文件并 stat（mtime/size），不读内容——增量快速判定用。"""
    crates_dir = os.path.join(repo_root, "rust", "crates")
    out: list[tuple[str, str, str]] = []
    for crate in sorted(os.listdir(crates_dir)):
        src_dir = os.path.join(crates_dir, crate, "src")
        if not os.path.isdir(src_dir):
            continue
        for dirpath, _dirs, names in os.walk(src_dir):
            for name in sorted(names):
                if name.endswith(".rs"):
                    abs_path = os.path.join(dirpath, name)
                    rel = os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
                    out.append((rel, crate, abs_path))
    return out


def stat_of(abs_path: str) -> tuple[float, int]:
    st = os.stat(abs_path)
    return (st.st_mtime, st.st_size)


def _list_files(repo_root: str, workers: int = 0, only: set[str] | None = None) -> CrateIndex:
    """收集文件清单/源码/哈希/crate 归属，不做语法解析。读取与哈希并行。

    only 给定时只读取该集合内文件（增量：未变文件不读内容）。
    """
    import multiprocessing as mp

    idx = CrateIndex(root=repo_root)
    paths: list[tuple[str, str]] = []
    for rel, crate, abs_path in list_rust_files(repo_root):
        idx.crates.setdefault(crate, os.path.dirname(os.path.dirname(abs_path)))
        if only is not None and rel not in only:
            idx.file_crate[rel] = crate
            continue
        paths.append((rel, abs_path))

    if workers <= 0:
        workers = min(8, (os.cpu_count() or 2))
    if workers > 1 and len(paths) > 1:
        with mp.Pool(workers) as pool:
            records = pool.map(_read_file, paths)
    else:
        records = [_read_file(p) for p in paths]
    for rel, raw, digest in records:
        idx.files[rel] = raw
        parts = rel.replace(os.sep, "/").split("/")
        idx.file_crate[rel] = parts[2] if len(parts) > 2 else parts[0]
        idx.file_hash[rel] = digest
    return idx


def _index_root(idx: CrateIndex, rel: str, raw: bytes, root: Node) -> None:
    crate = idx.file_crate[rel]
    under_src = os.path.relpath(rel, os.path.join(idx.crates[crate])).replace(os.sep, "/")
    rel_parts = [p for p in under_src.split("/") if p not in ("src",)]
    mod = _module_path(rel_parts)
    _index_sources(idx, root, raw)
    _index_file(idx, root, raw, crate, mod, rel)


def discover(repo_root: str, changed: set[str] | None = None,
             skeleton: dict[str, dict] | None = None) -> CrateIndex:
    """构建索引。

    changed 给定时只重新解析该集合内文件；skeleton 提供未变文件的函数 HIR 骨架
    （由解析缓存反序列化），使其完全跳过 tree-sitter。
    """
    idx = _list_files(repo_root)
    for rel, raw in sorted(idx.files.items()):
        if changed is not None and rel not in changed:
            if skeleton and rel in skeleton:
                _rebuild_from_skeleton(idx, rel, skeleton[rel])
            continue
        tree = PARSER.parse(raw)
        _index_root(idx, rel, raw, tree.root_node)
    return idx


def skeleton_of(idx: CrateIndex) -> dict[str, dict]:
    """把每个文件的函数 HIR 骨架转成可 JSON 化结构（不含 CST 节点）。"""
    owner_by_key: dict[str, str] = {}
    for method, owners in idx.method_owners.items():
        for owner, key in owners.items():
            owner_by_key[key] = owner
    out: dict[str, dict] = {"funcs": {}, "source_types": sorted(idx.source_types)}
    for key, fn in idx.funcs.items():
        s = fn.summary
        out["funcs"][key] = {
            "crate": s.crate, "module": s.module, "name": s.name, "file": s.file,
            "start_line": s.start_line, "end_line": s.end_line,
            "params": s.params, "param_types": s.param_types,
            "is_trait_object": s.is_trait_object, "body_hash": s.body_hash,
            "owner": owner_by_key.get(key, ""),
        }
    return out


def _rebuild_from_skeleton(idx: CrateIndex, rel: str, payload: dict) -> None:
    for ty in payload.get("source_types", []):
        idx.source_types.add(ty)
    for key, s in payload.get("funcs", {}).items():
        if s["file"] != rel:
            continue
        summ = FnSummary(
            key=key, crate=s["crate"], module=s["module"], name=s["name"], file=s["file"],
            start_line=s["start_line"], end_line=s["end_line"], params=s["params"],
            param_types=s["param_types"], is_trait_object=s["is_trait_object"],
            body_hash=s["body_hash"],
        )
        idx.funcs[key] = FnNode(summary=summ, node=None, src=idx.files[rel])
        idx.by_name.setdefault(s["name"], []).append(key)
        idx.by_method.setdefault(s["name"], []).append(key)
        if s.get("owner"):
            idx.method_owners.setdefault(s["name"], {})[s["owner"]] = key


def parse_one(raw: bytes):
    return PARSER.parse(raw).root_node


def discover_parallel(repo_root: str, workers: int = 0) -> CrateIndex:
    """全量并行解析：用线程池并发调 tree-sitter（C 扩展释放 GIL，CST 留在同进程，
    既绕开 Node 不能 pickle 的限制，又保留数据流阶段需要的真实节点）。"""
    from concurrent.futures import ThreadPoolExecutor

    idx = _list_files(repo_root, workers=workers)
    files = list(idx.files.items())
    if workers <= 0:
        workers = min(8, (os.cpu_count() or 2))

    def _parse(item):
        rel, raw = item
        return rel, PARSER.parse(raw).root_node

    if workers > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            roots = dict(pool.map(_parse, files))
    else:
        roots = {rel: PARSER.parse(raw).root_node for rel, raw in files}
    for rel, raw in files:
        _index_root(idx, rel, raw, roots[rel])
    return idx


def _index_sources(idx: CrateIndex, root: Node, src: bytes) -> None:
    """收集 impl ByteSource for XxxSource —— 自动发现污点源类型，不硬编码名字。

    该 grammar 把 trait 名表示为普通 type_identifier，目标类型在 for 关键字之后。
    """
    for imp in _find_all(root, "impl_item"):
        kids = [c for c in imp.children if c.is_named]
        type_ids = [c for c in kids if c.type == "type_identifier"]
        has_for = any(c.type == "for" for c in imp.children)
        if not has_for or not type_ids:
            continue
        # trait 名是第一个类型标识符，目标类型是 for 之后的第一个类型标识符
        trait_name = text(src, type_ids[0]).split("::")[-1]
        if trait_name != "ByteSource":
            continue
        for_pos = next(i for i, c in enumerate(imp.children) if c.type == "for")
        target = next((c for c in imp.children[for_pos + 1:]
                       if c.is_named and c.type in ("type_identifier", "generic_type")), None)
        if target is not None:
            idx.source_types.add(text(src, target).split("<")[0])


def _index_file(idx: CrateIndex, root: Node, src: bytes, crate: str, mod: str, rel: str) -> None:
    for fn in _find_all(root, "function_item"):
        name_node = first_of_type(fn, "identifier")
        name = text(src, name_node)
        params_node = first_of_type(fn, "parameters")
        pnames: list[str] = []
        ptypes: list[str] = []
        dyns: list[bool] = []
        for pm in children_of_type(params_node, "parameter") if params_node else []:
            pid = first_of_type(pm, "identifier")
            pty = None
            for c in pm.children:
                if c.type in ("reference_type", "scoped_type_identifier", "type_identifier",
                              "generic_type", "primitive_type", "array_type", "slice_type",
                              "tuple_type", "dynamic_type"):
                    pty = c
                    break
            pnames.append(text(src, pid))
            ptypes.append(type_last_name(pty, src))
            dyns.append(is_dyn(pty))
        block = first_of_type(fn, "block")
        key = f"{crate}::{mod + '::' if mod else ''}{name}"
        summ = FnSummary(
            key=key, crate=crate, module=mod, name=name,
            file=rel,
            start_line=fn.start_point[0] + 1,
            end_line=fn.end_point[0] + 1,
            params=pnames, param_types=ptypes, is_trait_object=dyns,
            body_hash=hash_block(block, src),
        )
        node = FnNode(summary=summ, node=fn, src=src)
        idx.funcs[key] = node
        idx.by_name.setdefault(name, []).append(key)
        idx.by_method.setdefault(name, []).append(key)
        owner = _impl_owner(fn, src)
        if owner:
            idx.method_owners.setdefault(name, {})[owner] = key
        # impl 内的方法同时按方法名登记（调用点 sink.restore_login(..) 只看得到方法名）
        _collect_callee_names(fn, src, idx, key)


def _impl_owner(fn: Node, src: bytes) -> str:
    """函数所在 impl 块的所有者类型末段名（无 impl 则为空串）。"""
    cur = fn.parent
    while cur is not None:
        if cur.type == "impl_item":
            has_for = any(c.type == "for" for c in cur.children)
            type_ids = [c for c in cur.children if c.type == "type_identifier"]
            if has_for and type_ids:
                # trait impl：for 之后的类型才是所有者
                for_pos = next(i for i, c in enumerate(cur.children) if c.type == "for")
                target = next((c for c in cur.children[for_pos + 1:] if c.is_named), None)
                return text(src, target).split("<")[0] if target else ""
            if type_ids:
                return text(src, type_ids[0]).split("<")[0]
        cur = cur.parent
    return ""


def _collect_callee_names(fn: Node, src: bytes, idx: CrateIndex, key: str) -> None:
    """登记函数体内直接出现的调用边（名字级，解析在数据流阶段做）。"""
    for call in _find_all(fn, "call_expression"):
        head = call.child_by_field_name("function")
        if head is None:
            continue
        if head.type == "field_expression":
            field = first_of_type(head, "field_identifier")
            idx.by_method.setdefault(text(src, field), [])
        elif head.type in ("identifier", "scoped_identifier"):
            tail = text(src, head).split("::")[-1]
            idx.by_name.setdefault(tail, [])


def _find_all(n: Node, ty: str) -> list[Node]:
    out: list[Node] = []
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type == ty:
            out.append(cur)
        stack.extend(cur.children)
    return out
