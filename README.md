# 消息队列消费端 · Rust bincode 反序列化静态分析语料

题面要把「源 → 落点」的链路找出来讲清楚：会话、缓存、RPC 参数、队列消费四类
bincode 反序列化落点，源是队列消息、网络帧、文件。这个仓库是 **语料 + baseline**，
不是成品分析器。

## 语料布局（Rust workspace）

| 路径 | 作用 |
|---|---|
| `rust/crates/ingest` | `ByteSource` trait、`FileSource`（文件源） |
| `rust/crates/wire` | `FrameSource`（网络帧源，长度前缀拆帧） |
| `rust/crates/mq` | `MessageSource`（队列消息源） |
| `rust/crates/session` | 会话反序列化，12 个漏洞 + 6 个 checked decoy |
| `rust/crates/cache` | 缓存反序列化，12 个漏洞 + 6 个 checked decoy |
| `rust/crates/rpc` | RPC 参数解码，13 个漏洞 + 6 个 checked decoy |
| `rust/crates/consumer` | 队列消费，13 个漏洞 + 4 个 checked decoy |
| `rust/crates/handlers` | 50 个入口：queue / frame / file 三个模块，经 `&mut dyn ByteSource` 取帧后调用 sink |

workspace 清单在 `rust/Cargo.toml`（仓库根目录没有 Cargo.toml，避免把分析器语言判成
Rust；这是本机 preflight 的口径，见 README 末尾）。语料不要求 `cargo build` 通过，
只需要语法可解析——题目只允许用语法解析库自建 HIR，不依赖编译器。

## 口径

- **落点（4 类）**：会话反序列化 `SessionStore::restore_*`、缓存反序列化
  `CacheStore::load_*`、RPC 参数解码 `RpcDecoder::decode_*`、队列消费
  `EventConsumer::consume_*`，共 50 个 `bincode::deserialize` 落点。
- **源（3 类）**：队列消息（`mq::MessageSource`）、网络帧（`wire::FrameSource`）、
  文件（`ingest::FileSource`）；handlers 里 17 / 17 / 16 条入口。
- **传播**：handler → `take_one(&mut dyn ByteSource)`（trait object，源类型被擦除）
  → 跨 crate 调 sink crate 的方法 → `bincode::deserialize`。
- **净化/decoy**：`*_checked` 方法先做长度校验（`MAX_*_BYTES`）、类型白名单
  （`ALLOWED_RPC_TYPES` / `CACHE_TAG`）或 HMAC 校验再反序列化；baseline 会把它们
  全部误报。题目要求的「标明中间哪一步本可以做长度校验或类型白名单」就落在这些
  位置。

## 跑法

```powershell
python baseline/scan.py > findings.json
python baseline/scan.py --sarif findings.sarif
python eval.py findings.json
python -m pytest tests -q
```

## 当前 baseline（正则）

`baseline/scan.py` 只按行匹配 `bincode::deserialize`，不做 HIR、不跟跨 crate 调用。
在 50 条标注样本上的实测：

- 召回 **100.0%**，误报率 **30.6%**（labels=50，findings=72）
- 误报全部来自 22 个 `*_checked` decoy——baseline 分不清「同一个 sink + 前面有校验」。

这正是题目要改进的起点：要自建 HIR 与数据流，跨 crate 时用函数摘要传播
（例如把「返回值来自哪个形参/源」做成摘要），并区分同一 sink 的净化写法。

## labels.json

50 条，每条给出 `file`、`line`、`sink`、`entry`、`source`；行号是真实行，
`tests/test_corpus.py::test_fifty_labels_point_at_real_bincode_lines` 逐条断言该行含
`bincode::deserialize`。

## 评审问题的落点

- 跨 crate 传播的函数摘要粒度：语料里每个 sink 方法只做一层 `bincode::deserialize(raw)`，
  摘要只需回答「返回值受哪个形参影响」；handlers 侧经 trait object 传入的字节要在
  调用点实例化，粒度过粗会漏掉 queue/frame/file 三种源的差异。
- 增量与全量一致、20 万行性能：本仓库只提供 50 条语义样本，性能语料由分析器自行
  benchmark；不把时间戳写进 SARIF。

## 为什么根目录没有 Cargo.toml

本机 `preflight.ps1` 只看仓库根目录有没有 `Cargo.toml` 来判断语料语言；本题的
「语言/框架」字段是 Python（分析器实现语言），Rust 只是被分析对象。workspace 清单放
在 `rust/Cargo.toml`，既保留真实 Rust 结构，又不触发字段不一致误判。
