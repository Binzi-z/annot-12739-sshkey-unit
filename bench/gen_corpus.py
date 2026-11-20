#!/usr/bin/env python3
"""生成 20 万行级合成 Rust workspace，结构与真实语料同构（source/trait object/sink/guard）。

放在独立临时目录，绝不污染被测仓库；生成器只产出可被 tree-sitter 解析的语法文本。
"""
from __future__ import annotations

import os
import sys

HEADER = '''use serde::Deserialize;
pub type Error = Box<dyn std::error::Error>;
const MAX_BYTES: usize = 4096;
const ALLOWED: [u8; 4] = [1, 2, 3, 4];
'''

TRAIT_SRC = '''pub trait ByteSource { fn next(&mut self) -> Option<Vec<u8>>; }
pub struct MqSource { pending: Vec<Vec<u8>> }
impl ByteSource for MqSource {
    fn next(&mut self) -> Option<Vec<u8>> { self.pending.pop() }
}
pub fn take_one(s: &mut dyn ByteSource) -> Result<Vec<u8>, Error> {
    s.next().ok_or_else(|| "eos".into())
}
'''


def gen(base: str, n_sink_crates: int, funcs_per_crate: int, handlers_per_module: int):
    crates = os.path.join(base, "rust", "crates")
    os.makedirs(crates, exist_ok=True)

    # 公共 source crate
    src_crate = os.path.join(crates, "bssrc", "src")
    os.makedirs(src_crate, exist_ok=True)
    with open(os.path.join(src_crate, "lib.rs"), "w", encoding="utf-8") as fh:
        fh.write(TRAIT_SRC)

    sink_crates = []
    for ci in range(n_sink_crates):
        cname = f"sinkc{ci:02d}"
        sink_crates.append(cname)
        cdir = os.path.join(crates, cname, "src")
        os.makedirs(cdir, exist_ok=True)
        with open(os.path.join(cdir, "lib.rs"), "w", encoding="utf-8") as fh:
            fh.write(HEADER)
            fh.write("#[derive(Clone, Deserialize)]\npub struct Val { pub id: u64, pub body: Vec<u8> }\n")
            fh.write("#[derive(Default)]\npub struct Store { seen: Vec<String> }\n")
            fh.write("impl Store {\n")
            for fi in range(funcs_per_crate):
                # 一半裸 sink，一半带长度/白名单守卫
                if fi % 2 == 0:
                    fh.write(f"    pub fn load_{fi:04d}(&mut self, raw: &[u8]) -> Result<Val, Error> {{\n")
                    fh.write("        let v: Val = bincode::deserialize(raw)?;\n")
                    fh.write(f"        self.seen.push(\"{fi}\".into()); Ok(v)\n    }}\n")
                else:
                    fh.write(f"    pub fn load_{fi:04d}_checked(&mut self, raw: &[u8]) -> Result<Val, Error> {{\n")
                    fh.write("        if raw.len() > MAX_BYTES || !raw.first().map(|b| ALLOWED.contains(b)).unwrap_or(false) {\n")
                    fh.write("            return Err(\"rejected\".into());\n        }\n")
                    fh.write("        let v: Val = bincode::deserialize(raw)?;\n")
                    fh.write(f"        self.seen.push(\"{fi}\".into()); Ok(v)\n    }}\n")
            fh.write("}\n")

    # handler crate：大量入口经 take_one(trait object) 调各 sink
    hdir = os.path.join(crates, "handlers", "src")
    os.makedirs(hdir, exist_ok=True)
    with open(os.path.join(hdir, "lib.rs"), "w", encoding="utf-8") as fh:
        fh.write("mod gen;\n")
    total_handlers = 0
    with open(os.path.join(hdir, "gen.rs"), "w", encoding="utf-8") as fh:
        fh.write("use bssrc::{take_one, MqSource};\n")
        for ci, cname in enumerate(sink_crates):
            fh.write(f"use {cname}::Store;\n")
        for hi in range(handlers_per_module):
            ci = hi % len(sink_crates)
            fi = (hi // len(sink_crates)) % funcs_per_crate
            method = f"load_{fi:04d}" if fi % 2 == 0 else f"load_{fi:04d}_checked"
            fh.write(f"pub fn handle_{hi:05d}(source: &mut MqSource) -> Result<(), Error> {{\n")
            fh.write("    let raw = take_one(source)?;\n")
            fh.write("    let mut sink = Store::default();\n")
            fh.write(f"    sink.{method}(&raw)?;\n    Ok(())\n}}\n")
            total_handlers += 1

    # workspace 清单
    with open(os.path.join(base, "rust", "Cargo.toml"), "w", encoding="utf-8") as fh:
        fh.write("[workspace]\nmembers = [\n")
        fh.write('  "crates/bssrc",\n')
        for cname in sink_crates:
            fh.write(f'  "crates/{cname}",\n')
        fh.write('  "crates/handlers",\n]\n')
    return total_handlers


if __name__ == "__main__":
    base = sys.argv[1]
    n_crates = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    fpc = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    nh = int(sys.argv[4]) if len(sys.argv) > 4 else 8000
    h = gen(base, n_crates, fpc, nh)
    total = 0
    for dirpath, _d, names in os.walk(os.path.join(base, "rust")):
        for n in names:
            if n.endswith(".rs"):
                total += sum(1 for _ in open(os.path.join(dirpath, n), encoding="utf-8"))
    print(f"handlers={h} total_rust_lines={total}")
