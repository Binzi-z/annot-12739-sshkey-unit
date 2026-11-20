"""阶段二：自建过程内数据流 + 函数摘要 + 跨 crate 实例化。

设计要点（对应题面的函数摘要粒度问题，详见 README 与文末注释）：
  - 摘要按「函数」为单位、按「形参下标」做污点槽，上下文不敏感、流敏感（块内语句序 +
    早返回守卫作用域），每个函数只算一次并缓存；
  - 入口处只做一次轻量实例化：把形参槽绑定到具体源（queue/frame/file），沿调用图
    替换符号 Origin，trait object 调用点在实例化时按实参类型落地；
  - 守卫（长度/白名单/tag/HMAC）在 HIR 上按语句形态识别，记录被守卫的符号 Origin，
    与同一 sink 的无守卫写法区分开——这是压误报的关键。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from .hir import FnSummary, Guard, Origin, SinkEffect, first_of_type, text, unwrap
from .index import CrateIndex, FnNode

SOURCE_TYPE_KIND = {
    "MessageSource": "queue_message",
    "FrameSource": "network_frame",
    "FileSource": "file",
}
SINK_RULE_BY_CRATE = {
    "session": ("DESER-SESSION-001", "session"),
    "cache": ("DESER-CACHE-002", "cache"),
    "rpc": ("DESER-RPC-003", "rpc"),
    "consumer": ("DESER-MQ-004", "mq"),
}
DEFAULT_SINK_RULE = ("DESER-BINCODE-001", "bincode")
GUARD_KIND_HINT = {
    "length": "长度上限校验（如 raw.len() <= MAX_*_BYTES）",
    "whitelist": "类型白名单校验（如 ALLOWED_RPC_TYPES.contains(..)）",
    "tag": "类型 tag 校验（如 raw.first() == CACHE_TAG）",
    "hmac": "HMAC/签名校验（如 verify_signature(raw)）",
}


@dataclass(frozen=True)
class CallRec:
    """摘要里的一次调用记录：被调函数（解析后可能多个候选）+ 各实参的符号 Origin。"""
    callee_keys: tuple
    line: int
    arg_origins: tuple                 # 每个实参一个 frozenset[Origin]
    receiver_origins: tuple            # 接收者的 Origin 集合（方法调用）
    method_name: str
    head_text: str


@dataclass
class BuiltSummary:
    return_origins: tuple
    sink_effects: list[SinkEffect]
    calls: list[CallRec]


# ---------------------------------------------------------------- 引擎

class DataflowEngine:
    def __init__(self, idx: CrateIndex):
        self.idx = idx
        self._cache: dict[str, BuiltSummary] = {}
        self._stack: set[str] = set()
        self.changed_keys: set[str] | None = None  # 增量模式下需要重算的函数闭包

    # ================================================================ 摘要序列化

    def dump_summaries(self, file_of: dict[str, str]) -> dict[str, dict]:
        """把当前内存里的 BuiltSummary 转成可 JSON 化的过程内摘要。"""
        out: dict[str, dict] = {}
        for key, built in self._cache.items():
            out[key] = {
                "return_origins": [origin_to_dict(o) for o in built.return_origins],
                "sink_effects": [effect_to_dict(e) for e in built.sink_effects],
                "calls": [{
                    "callee_keys": list(c.callee_keys), "line": c.line,
                    "arg_origins": [[origin_to_dict(o) for o in ao] for c2 in [c] for ao in c2.arg_origins],
                    "receiver_origins": [origin_to_dict(o) for o in c.receiver_origins],
                    "method_name": c.method_name, "head_text": c.head_text,
                } for c in built.calls],
            }
        per_file: dict[str, dict] = {}
        for key, blob in out.items():
            per_file.setdefault(file_of[key], {})[key] = blob
        return per_file

    def load_summaries(self, per_file: dict[str, dict], unchanged_files: set[str]) -> int:
        """增量：把未变文件的摘要直接回填，跳过其重算。返回回填条数。"""
        n = 0
        for file, blobs in per_file.items():
            if file not in unchanged_files:
                continue
            for key, blob in blobs.items():
                if key not in self.idx.funcs or key in self._cache:
                    continue
                self._cache[key] = _built_from_blob(blob)
                n += 1
        return n

    # ================================================================ 摘要构建

    def summarize(self, key: str) -> BuiltSummary:
        if key in self._cache:
            return self._cache[key]
        # 增量惰性命中：未变函数的摘要以 dict 形式挂在索引上，首次访问才物化
        lazy = getattr(self.idx, "_lazy_summary_blobs", None)
        if lazy is not None and key in lazy:
            built = _built_from_blob(lazy[key])
            self._cache[key] = built
            return built
        if self.changed_keys is not None and key not in self.changed_keys and key in self.idx.funcs:
            # 增量闭包外且无缓存：兜底空摘要，不展开重算
            return BuiltSummary((), [], [])
        if key in self._stack:  # 递归：本轮先给空摘要，定点后由调用方保守处理
            return BuiltSummary((), [], [])
        self._stack.add(key)
        try:
            fn = self.idx.funcs[key]
            if fn.node is None:
                # 骨架函数且无缓存摘要：无 CST 可遍历，保守返回空摘要（不伪造数据流）
                built = BuiltSummary((), [], [])
                self._cache[key] = built
                return built
            env: dict[str, frozenset[Origin]] = {
                name: frozenset([Origin(kind="param", index=i)])
                for i, name in enumerate(fn.summary.params)
            }
            types = {name: fn.summary.param_types[i] for i, name in enumerate(fn.summary.params)}
            effects: list[SinkEffect] = []
            calls: list[CallRec] = []
            rets: set[Origin] = set()
            block = first_of_type(fn.node, "block")
            self._walk_block(key, block, fn.src, env, types, frozenset(), (key,), effects, calls, rets)
            built = BuiltSummary(tuple(sorted(rets, key=origin_key)), effects, calls)
            self._cache[key] = built
            return built
        finally:
            self._stack.discard(key)

    # ------------------------------------------------------------ 块/语句遍历

    def _walk_block(self, key, block: Node | None, src, env, types, guards, chain,
                    effects, calls, rets) -> None:
        if block is None:
            return
        local_env = dict(env)
        local_guards = frozenset(guards)
        named = [c for c in block.children if c.is_named and c.type not in ("{", "}")]
        for idx_stmt, stmt in enumerate(named):
            if stmt.type == "let_declaration":
                self._do_let(key, stmt, src, local_env, types, local_guards, chain,
                             effects, calls, rets)
            elif stmt.type == "expression_statement":
                expr = stmt.children[0] if stmt.children else stmt
                self._eval_stmt_expr(key, expr, src, local_env, types, local_guards, chain,
                                     effects, calls, rets)
                # 早返回形态的守卫 if：if <cond on tainted> { return Err(..) }
                new_guards = self._guard_from_if(expr, src, local_env)
                if new_guards:
                    local_guards = local_guards | new_guards
            elif stmt.type == "if_expression":
                self._do_if(key, stmt, src, local_env, types, local_guards, chain,
                            effects, calls, rets)
            elif stmt.type == "match_expression":
                self._do_match(key, stmt, src, local_env, types, local_guards, chain,
                               effects, calls, rets)
            elif stmt.type in ("loop_expression", "while_expression", "for_expression"):
                body = first_of_type(stmt, "block")
                self._walk_block(key, body, src, local_env, types, local_guards, chain,
                                 effects, calls, rets)
            elif stmt.type == "return_expression":
                val = None
                for c in stmt.children:
                    if c.is_named and c.type != "return":
                        val = c
                        break
                if val is not None:
                    rets |= self._eval(val, src, local_env, types, local_guards, chain,
                                       effects, calls)
            elif stmt.type == "call_expression":
                # 块末隐式返回表达式：其污点进入函数返回值
                if idx_stmt == len(named) - 1:
                    rets |= self._eval(stmt, src, local_env, types, local_guards, chain,
                                       effects, calls)
                else:
                    self._eval(stmt, src, local_env, types, local_guards, chain,
                               effects, calls)
            # 其它语句形态（item 声明等）与污点无关，跳过

    def _do_let(self, key, stmt, src, env, types, guards, chain, effects, calls, rets):
        name_node = first_of_type(stmt, "identifier")
        if name_node is None:
            return
        name = text(src, name_node)
        init = None
        for c in stmt.children:
            if c.is_named and c.type not in ("let", "identifier", "mutable_specifier",
                                             "type_identifier", "scoped_type_identifier",
                                             "generic_type", "reference_type", "primitive_type"):
                init = c
                break
        if init is None:
            env[name] = frozenset()
            return
        origins = self._eval(init, src, env, types, guards, chain, effects, calls)
        env[name] = origins
        types[name] = self._infer_type(init, src, types)

    def _eval_stmt_expr(self, key, expr, src, env, types, guards, chain, effects, calls, rets):
        if expr.type == "if_expression":
            self._do_if(key, expr, src, env, types, guards, chain, effects, calls, rets)
        else:
            self._eval(expr, src, env, types, guards, chain, effects, calls)

    def _do_if(self, key, node, src, env, types, guards, chain, effects, calls, rets):
        # 条件本身可能含调用（如 !verify_signature(raw)）
        cond = node.child_by_field_name("condition")
        if cond is not None:
            self._eval(cond, src, env, types, guards, chain, effects, calls)
        blocks = [c for c in node.children if c.type == "block"]
        alt = first_of_type(node, "else_clause")
        if alt is not None:
            blocks += [c for c in alt.children if c.type == "block"]
        for b in blocks:
            self._walk_block(key, b, src, env, types, guards, chain, effects, calls, rets)

    def _do_match(self, key, node, src, env, types, guards, chain, effects, calls, rets):
        scrut = node.child_by_field_name("value")
        if scrut is not None:
            self._eval(scrut, src, env, types, guards, chain, effects, calls)
        for arm in children_of_type_local(node, "match_arm"):
            body = arm.children[-1]
            if body.type == "block":
                self._walk_block(key, body, src, env, types, guards, chain, effects, calls, rets)
            else:
                self._eval(body, src, env, types, guards, chain, effects, calls)

    # ------------------------------------------------------------ 表达式求值

    def _eval(self, node: Node, src, env, types, guards, chain, effects, calls) -> frozenset[Origin]:
        node = unwrap(node)
        t = node.type
        if t == "identifier":
            return env.get(text(src, node), frozenset())
        if t == "reference_expression":
            inner = node.children[-1]
            return self._eval(inner, src, env, types, guards, chain, effects, calls)
        if t == "parenthesized_expression":
            inner = next((c for c in node.children if c.is_named), None)
            return self._eval(inner, src, env, types, guards, chain, effects, calls) if inner else frozenset()
        if t in ("index_expression", "field_expression"):
            base = node.child_by_field_name("value") or node.children[0]
            return self._eval(base, src, env, types, guards, chain, effects, calls)
        if t == "binary_expression":
            out: set[Origin] = set()
            for c in node.children:
                if c.is_named and c.type != "bracket_type":
                    out |= self._eval(c, src, env, types, guards, chain, effects, calls)
            return frozenset(out)
        if t == "unary_expression":
            inner = next((c for c in node.children if c.is_named), None)
            return self._eval(inner, src, env, types, guards, chain, effects, calls) if inner else frozenset()
        if t == "call_expression":
            return self._eval_call(node, src, env, types, guards, chain, effects, calls)
        if t == "try_expression":
            inner = next((c for c in node.children if c.is_named), None)
            return self._eval(inner, src, env, types, guards, chain, effects, calls) if inner else frozenset()
        if t == "if_expression":
            self._do_if(None, node, src, env, types, guards, chain, effects, calls, set())
            return frozenset()
        # 字面量/闭包/构造等：无外部污点
        return frozenset()

    def _eval_call(self, call: Node, src, env, types, guards, chain, effects, calls) -> frozenset[Origin]:
        head = call.child_by_field_name("function")
        args_node = call.child_by_field_name("arguments")
        arg_nodes = [c for c in args_node.children if c.is_named] if args_node else []
        arg_origin_list = [self._eval(a, src, env, types, guards, chain, effects, calls)
                           for a in arg_nodes]
        line = call.start_point[0] + 1
        head_text = text(src, head)

        # 1) bincode 落点：记录 SinkEffect（守卫随当前作用域带上）
        if head_text.split("::")[0] == "bincode" and "deserialize" in head_text:
            feed = arg_origin_list[0] if arg_origin_list else frozenset()
            rule, kind = SINK_RULE_BY_CRATE.get(chain[0].split("::")[0],
                                                DEFAULT_SINK_RULE)
            effects.append(SinkEffect(
                callee_key=chain[0], sink_rule=rule, sink_kind=kind, line=line,
                arg_origins=tuple(sorted(feed, key=origin_key)),
                guards=tuple(guards), call_chain=tuple(chain),
            ))
            return frozenset()  # 反序列化产物是新值，不沿字节继续传播

        receiver_origins: frozenset[Origin] = frozenset()
        method_name = ""
        if head.type == "field_expression":
            method_name = text(src, first_of_type(head, "field_identifier"))
            recv = head.child_by_field_name("value")
            if recv is not None:
                # recv 本身可能是 source.next() 这样的内层调用链，需要先求值
                receiver_origins = self._eval(recv, src, env, types, guards, chain,
                                              effects, calls)
        elif head.type == "call_expression":
            # 方法链：foo.next().ok_or_else(..) —— 先求内层调用，其污点作为接收者
            receiver_origins = self._eval(head, src, env, types, guards, chain,
                                          effects, calls)
            inner_head = head.child_by_field_name("function")
            if inner_head is not None and inner_head.type == "field_expression":
                method_name = text(src, first_of_type(inner_head, "field_identifier"))

        # 2) 解析被调函数（方法按接收者类型过滤；自由函数按名查全局符号）
        recv_type = ""
        if head.type == "field_expression":
            recv_node = head.child_by_field_name("value")
            if recv_node is not None and recv_node.type == "identifier":
                recv_type = types.get(text(src, recv_node), "")
        callee_keys = self._resolve(head, head_text, method_name, recv_type=recv_type)
        rec = CallRec(
            callee_keys=tuple(callee_keys), line=line,
            arg_origins=tuple(arg_origin_list),
            receiver_origins=tuple(sorted(receiver_origins, key=origin_key)),
            method_name=method_name, head_text=head_text,
        )
        calls.append(rec)

        # 3) 内联应用已知函数摘要（上下文不敏感：形参槽 <- 实参 Origin）
        out: set[Origin] = set()
        for ck in callee_keys:
            if ck in chain:
                continue
            sub = self.summarize(ck)
            bind: dict[int, frozenset[Origin]] = {}
            fn = self.idx.funcs[ck].summary
            for i, ao in enumerate(arg_origin_list):
                if i < len(fn.params):
                    bind[i] = ao
            for eff in sub.sink_effects:
                mapped_args = self._map_origins(eff.arg_origins, bind)
                if not mapped_args:
                    continue  # 喂给落点的字节在本上下文不可达
                mapped_guards = self._map_guards(eff.guards, bind)
                effects.append(SinkEffect(
                    callee_key=eff.callee_key, sink_rule=eff.sink_rule, sink_kind=eff.sink_kind,
                    line=eff.line,
                    arg_origins=tuple(sorted(mapped_args, key=origin_key)),
                    guards=tuple(guards) + tuple(mapped_guards),
                    call_chain=chain + eff.call_chain,
                ))
            for o in sub.return_origins:
                if o.kind == "param" and o.index in bind:
                    # 穿过本次调用：在来源 Origin 上追加 (被调函数, 调用点行号) 传播边
                    for src_o in bind[o.index]:
                        out.add(src_o.through(ck, line))
                else:
                    out.add(o)

        # 4) 解析不到或候选均为递归/无摘要的调用：
        #    方法链上的透传方法（ok_or_else/unwrap/expect...）与虚分派（trait object）
        #    保守地把接收者污点并入返回值，保证 trait object 擦除后源信息不丢。
        effective = [ck for ck in callee_keys if ck not in chain]
        if not effective and receiver_origins:
            out |= set(receiver_origins)
        elif callee_keys and not out and receiver_origins:
            # 候选函数体没有可表达的返回摘要（如 next() 直接 pop 容器），退回接收者
            out |= set(receiver_origins)
        if not callee_keys and not receiver_origins and head.type != "field_expression":
            # 自由函数无函数体可摘要时，实参污点保守透传到返回值
            for ao in arg_origin_list:
                out |= set(ao)
        return frozenset(out)

    # ------------------------------------------------------------ 调用解析

    def _resolve(self, head: Node, head_text: str, method_name: str, recv_type: str) -> list[str]:
        if head.type == "scoped_identifier":
            return self.idx.resolve_fn(head_text)
        if head.type == "identifier":
            return [k for k in self.idx.resolve_fn(head_text) if "::" in k]
        if head.type == "field_expression" and method_name:
            # 类型化解析优先：接收者类型明确时只内联该 impl 的方法，避免同名跨 crate 串味
            return self.idx.resolve_method(method_name, recv_type)
        return []

    def _owner_type(self, fn_key: str) -> str:
        # 语料里方法均为 impl XxxStore { fn method(..) }，owner 取文件内 impl 目标名
        fn = self.idx.funcs.get(fn_key)
        if not fn:
            return ""
        for imp in _find_parents(fn.node, "impl_item"):
            ty = first_of_type(imp, "type_identifier") or first_of_type(imp, "generic_type")
            if ty is not None:
                return text(fn.src, ty).split("<")[0]
        return ""

    # ------------------------------------------------------------ 守卫识别

    def _guard_from_if(self, expr: Node, src, env) -> frozenset[Guard]:
        if expr is None or expr.type != "if_expression":
            return frozenset()
        block = first_of_type(expr, "block")
        if not _block_returns_early(block):
            return frozenset()
        cond = expr.child_by_field_name("condition")
        kind, touched = _classify_guard(cond, src)
        if kind is None:
            return frozenset()
        origins: set[Origin] = set()
        for v in touched:
            origins |= set(env.get(v, frozenset()))
        if not origins:
            return frozenset()
        return frozenset([Guard(guard_kind=kind, line=expr.start_point[0] + 1,
                                detail=text(src, cond), guarded=frozenset(origins))])

    def _map_origins(self, origins, bind):
        out: set[Origin] = set()
        for o in origins:
            if o.kind == "param":
                out |= set(bind.get(o.index, frozenset()))
            else:
                out.add(o)
        return out

    def _map_guards(self, guards, bind):
        out = []
        for g in guards:
            mapped = set()
            for o in g.guarded:
                if o.kind == "param":
                    mapped |= set(bind.get(o.index, frozenset()))
                else:
                    mapped.add(o)
            if mapped:
                out.append(Guard(guard_kind=g.guard_kind, line=g.line, detail=g.detail))
        return out

    def _infer_type(self, init: Node, src, types) -> str:
        init = unwrap(init)
        if init.type == "call_expression":
            head = init.child_by_field_name("function")
            ht = text(src, head)
            if head.type == "scoped_identifier" and "::" in ht:
                return ht.split("::")[0]
            if head.type == "identifier":
                for k in self.idx.resolve_fn(ht):
                    fn = self.idx.funcs[k].summary
                    # ByteSource 取帧函数的返回值是 Vec<u8>，其余退回首个形参类型
                    return "Vec" if any(t == "ByteSource" for t in fn.param_types) else \
                        (fn.param_types[0] if fn.param_types else "")
        if init.type == "identifier":
            return types.get(text(src, init), "")
        return ""


# ---------------------------------------------------------------- 局部工具

def origin_key(o: Origin):
    return (o.kind, o.index, o.name, o.hops)


def _built_from_blob(blob: dict) -> "BuiltSummary":
    return BuiltSummary(
        return_origins=tuple(origin_from_dict(d) for d in blob["return_origins"]),
        sink_effects=[effect_from_dict(d) for d in blob["sink_effects"]],
        calls=[CallRec(
            callee_keys=tuple(c["callee_keys"]), line=c["line"],
            arg_origins=tuple(frozenset(origin_from_dict(o) for o in ao)
                              for ao in c["arg_origins"]),
            receiver_origins=tuple(origin_from_dict(o) for o in c["receiver_origins"]),
            method_name=c["method_name"], head_text=c["head_text"],
        ) for c in blob["calls"]],
    )


def origin_to_dict(o: Origin) -> dict:
    return {"kind": o.kind, "index": o.index, "name": o.name,
            "hops": [[k, ln] for k, ln in o.hops]}


def origin_from_dict(d: dict) -> Origin:
    return Origin(kind=d["kind"], index=d["index"], name=d["name"],
                  hops=tuple((k, ln) for k, ln in d.get("hops", [])))


def effect_to_dict(e: SinkEffect) -> dict:
    return {
        "callee_key": e.callee_key, "sink_rule": e.sink_rule,
        "sink_kind": e.sink_kind, "line": e.line,
        "arg_origins": [origin_to_dict(o) for o in e.arg_origins],
        "guards": [{"guard_kind": g.guard_kind, "line": g.line, "detail": g.detail,
                    "guarded": [origin_to_dict(o) for o in g.guarded]} for g in e.guards],
        "call_chain": list(e.call_chain),
    }


def effect_from_dict(d: dict) -> SinkEffect:
    return SinkEffect(
        callee_key=d["callee_key"], sink_rule=d["sink_rule"], sink_kind=d["sink_kind"],
        line=d["line"],
        arg_origins=tuple(origin_from_dict(o) for o in d["arg_origins"]),
        guards=tuple(Guard(guard_kind=g["guard_kind"], line=g["line"], detail=g["detail"],
                           guarded=frozenset(origin_from_dict(o) for o in g["guarded"]))
                     for g in d["guards"]),
        call_chain=tuple(d["call_chain"]),
    )


def reverse_closure(idx: CrateIndex, changed_files: set[str],
                    cached_summaries: dict | None = None) -> set[str]:
    """受变更文件影响的函数闭包：变更文件内函数 + 经调用边反向可达的全部函数。

    反向边优先取已缓存摘要里的 CallRec（纯数据，不依赖 CST）；
    缓存缺失的函数才退回 CST 遍历，从而兼容「node=None 的骨架文件」。
    """
    changed = {k for k, fn in idx.funcs.items() if fn.summary.file in changed_files}
    rev: dict[str, set[str]] = {}

    def add_edge(caller: str, name: str) -> None:
        for target in tuple(idx.by_method.get(name, ())) + tuple(idx.by_name.get(name, ())):
            rev.setdefault(target, set()).add(caller)

    for key, fn in idx.funcs.items():
        blob = (cached_summaries or {}).get(key)
        if blob is not None:
            for c in blob.get("calls", []):
                name = c.get("method_name") or c.get("head_text", "").split("::")[-1]
                if name:
                    add_edge(key, name)
        elif fn.node is not None:
            # 仅当某函数既无缓存摘要又有 CST（本次新解析的变更文件）才回退到语法遍历
            for call in _find_all(fn.node, "call_expression"):
                head = call.child_by_field_name("function")
                if head is None:
                    continue
                if head.type == "field_expression":
                    name = text(fn.src, first_of_type(head, "field_identifier"))
                elif head.type in ("identifier", "scoped_identifier"):
                    name = text(fn.src, head).split("::")[-1]
                else:
                    continue
                add_edge(key, name)
    seen, stack = set(changed), list(changed)
    while stack:
        cur = stack.pop()
        for caller in rev.get(cur, ()):
            if caller not in seen:
                seen.add(caller)
                stack.append(caller)
    return seen


def children_of_type_local(n: Node, ty: str):
    return [c for c in n.children if c.type == ty]


def _find_parents(n: Node, ty: str):
    out, cur = [], n.parent
    while cur is not None:
        if cur.type == ty:
            out.append(cur)
        cur = cur.parent
    return out


def _block_returns_early(block: Node | None) -> bool:
    """守卫块是否在条件成立时终止当前路径（return / panic 类宏 / 提前 Err）。"""
    if block is None:
        return False
    for c in block.children:
        if c.type in ("return_expression", "macro_invocation"):
            return True
        if c.type == "expression_statement" and c.children:
            inner = c.children[0]
            if inner.type == "return_expression":
                return True
    return False


def _classify_guard(cond: Node | None, src) -> tuple[str | None, set[str]]:
    """按 HIR 语句形态（非正则、非现成规则）识别四类守卫，返回 (种类, 触碰的变量名)。"""
    if cond is None:
        return None, set()
    blob = text(src, cond)
    touched = {text(src, i) for i in _find_all(cond, "identifier")}

    has_len = any(text(src, c) == "len" for c in _find_all(cond, "field_identifier"))
    has_contains = "contains" in blob
    has_first = "first" in blob
    has_verify = "verify_signature" in blob or "verify_hmac" in blob or "hmac" in blob.lower()
    consts = [text(src, i) for i in _find_all(cond, "identifier")
              if text(src, i).startswith(("MAX_", "ALLOWED_", "CACHE_"))]

    if has_verify:
        return "hmac", touched
    if has_contains and any(c.startswith("ALLOWED_") for c in consts):
        return "whitelist", touched
    if has_first and any(c.startswith("CACHE_") for c in consts):
        return "tag", touched
    if has_len and any(c.startswith("MAX_") for c in consts):
        return "length", touched
    # 退化形态：长度比较但常量名不规范，仍按长度守卫识别
    if has_len and (">" in blob or "<" in blob):
        return "length", touched
    return None, touched


def _find_all(n: Node, ty: str):
    out, stack = [], [n]
    while stack:
        cur = stack.pop()
        if cur.type == ty:
            out.append(cur)
        stack.extend(cur.children)
    return out
