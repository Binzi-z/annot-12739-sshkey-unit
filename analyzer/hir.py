"""HIR：基于 tree-sitter 语法库自建的高层中间表示。

题面约束：只允许语法解析库，不许用现成规则 / 编译器。
tree-sitter 只负责把源码变成 CST；下面的 HIR（函数、调用、守卫、变量类型环境、
污点摘要）全部由本项目自己定义和构建，不引入任何现成污点/审计规则。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from tree_sitter import Node

# ---------------------------------------------------------------- 语法树小工具

def text(src: bytes, n: Node | None) -> str:
    if n is None:
        return ""
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def children_of_type(n: Node, ty: str) -> list[Node]:
    return [c for c in n.children if c.type == ty]


def first_of_type(n: Node, ty: str) -> Node | None:
    for c in n.children:
        if c.type == ty:
            return c
    return None


def unwrap(n: Node) -> Node:
    """剥掉 try_expression(?) / reference_expression(&) / 括号等包装节点。"""
    while n.type in {"try_expression", "reference_expression", "parenthesized_expression"}:
        inner = first_of_type(n, "call_expression") or first_of_type(n, "identifier")
        if inner is None:
            for c in n.children:
                if c.is_named and c.type not in {"?", "&", "(", ")"}:
                    inner = c
                    break
        if inner is None:
            break
        n = inner
    return n


# ---------------------------------------------------------------- HIR 数据模型

@dataclass(frozen=True)
class Origin:
    """污点来源的抽象符号（具体来源在入口实例化阶段才绑定）。

    hops 记录该污点穿过的跨函数传播边 (函数 key, 调用点行号)，
    使不含 sink 的中转函数（如 take_one 这层 trait object 擦除点）
    也能出现在最终 codeFlow 里。
    """
    kind: str          # "param" | "source"
    index: int = -1    # param 时为形参下标
    name: str = ""     # source 时为 queue_message/network_frame/file
    hops: tuple = ()

    def __str__(self) -> str:
        if self.kind == "param":
            return f"arg{self.index}"
        return f"<{self.name}>"

    def through(self, fn_key: str, line: int) -> "Origin":
        return Origin(kind=self.kind, index=self.index, name=self.name,
                      hops=self.hops + ((fn_key, line),))


@dataclass(frozen=True)
class Guard:
    """一次净化（长度校验 / 类型白名单 / tag 校验 / HMAC）。"""
    guard_kind: str    # length | whitelist | tag | hmac
    line: int
    detail: str
    guarded: frozenset = frozenset()   # 被守卫字节对应的 Origin 集合


@dataclass(frozen=True)
class SinkEffect:
    """函数体内（含内联展开的被调函数）一个 bincode 落点的 HIR 记录。"""
    callee_key: str          # 拥有该 bincode 调用的函数全限定名
    sink_rule: str           # DESER-SESSION-001 ...
    sink_kind: str           # session/cache/rpc/mq
    line: int                # bincode 所在真实行
    arg_origins: tuple       # 喂给 bincode 的字节对应的 Origin 集合
    guards: tuple            # 到达该落点前对这些字节生效的 Guard
    call_chain: tuple        # 从当前函数到落点的函数名链


@dataclass
class FnSummary:
    """跨 crate 传播的最小单元：函数摘要（详见 summary.py 的粒度说明）。"""
    key: str                          # crate::模块路径::函数名
    crate: str
    module: str
    name: str
    file: str
    start_line: int
    end_line: int
    params: list[str]                 # 形参名（按下标）
    param_types: list[str]            # 形参类型的末段名（MessageSource / [u8] / dyn ByteSource ...）
    is_trait_object: list[bool]       # 该形参是否为 dyn trait object
    return_origins: tuple = ()        # 返回值受哪些形参/源影响
    sink_effects: list[SinkEffect] = field(default_factory=list)
    callees: set[str] = field(default_factory=set)
    body_hash: str = ""

    def label(self) -> str:
        return f"{self.key} ({self.file}:{self.start_line})"


# ---------------------------------------------------------------- 类型名提取

def type_last_name(ty: Node, src: bytes) -> str:
    """取类型的末段标识符，mq::MessageSource -> MessageSource，&mut dyn T -> T，&[u8] -> [u8]。"""
    if ty is None:
        return ""
    if ty.type == "reference_type":
        inner = first_of_type(ty, "dynamic_type") or first_of_type(ty, "scoped_type_identifier") \
            or first_of_type(ty, "type_identifier") or first_of_type(ty, "generic_type") \
            or first_of_type(ty, "slice_type") or first_of_type(ty, "array_type")
        return type_last_name(inner, src) if inner else ""
    if ty.type == "dynamic_type":
        return text(src, first_of_type(ty, "type_identifier"))
    if ty.type == "scoped_type_identifier":
        ids = [c for c in ty.children if c.type in ("identifier", "type_identifier")]
        return text(src, ids[-1]) if ids else ""
    if ty.type == "generic_type":
        return text(src, first_of_type(ty, "type_identifier"))
    if ty.type in ("type_identifier", "primitive_type"):
        return text(src, ty)
    if ty.type in ("slice_type", "array_type"):
        prim = first_of_type(ty, "primitive_type")
        return f"[{text(src, prim)}]" if prim else ty.type
    # 其它复合类型（元组等）：抓里面第一个标识符
    n = first_of_type(ty, "type_identifier") or first_of_type(ty, "primitive_type")
    return text(src, n) if n else ty.type


def is_dyn(ty: Node) -> bool:
    return ty is not None and (ty.type == "dynamic_type" or
                               (ty.type == "reference_type" and first_of_type(ty, "dynamic_type") is not None))


def hash_block(block: Node | None, src: bytes) -> str:
    if block is None:
        return hashlib.blake2b(b"", digest_size=16).hexdigest()
    return hashlib.blake2b(src[block.start_byte:block.end_byte], digest_size=16).hexdigest()
