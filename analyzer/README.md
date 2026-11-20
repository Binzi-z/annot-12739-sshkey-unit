# bincode HIR 污点分析器

只依赖 **tree-sitter（语法解析库）**，HIR、数据流、函数摘要、跨 crate / trait object
传播、守卫识别全部自建，不用任何现成污点/审计规则。

## 1. 要解决的问题

未校验字节从三类源进入、直达四类 `bincode::deserialize` 落点：

| 源 | 入口特征 | 落点（4 类） |
|---|---|---|
| 队列消息 `mq::MessageSource` | 形参是实现 `ByteSource` 的源类型 | 会话 `SessionStore::restore_*` |
| 网络帧 `wire::FrameSource` | 同上 | 缓存 `CacheStore::load_*` |
| 文件 `ingest::FileSource` | 同上 | RPC `RpcDecoder::decode_*` |
| | | 队列消费 `EventConsumer::consume_*` |

传播形态：`handler -> take_one(&mut dyn ByteSource)（trait object，源类型被擦除）
-> 跨 crate 调 sink 方法 -> bincode::deserialize`。
带 `*_checked` 的方法在反序列化前有长度上限 / 类型白名单 / tag / HMAC 校验，是必须
正确排除的 decoy。

## 2. 流水线（三层）

```
tree-sitter CST
   │  index.py：自建符号表、impl 归属、源类型发现（impl ByteSource for X）
   ▼
HIR（FnSummary 骨架：形参/类型/行号/方法所有者/body 哈希）
   │  dataflow.py：过程内流敏感数据流 + 守卫识别 + 函数摘要
   ▼
函数摘要（return_origins / sink_effects / calls）
   │  driver.py：入口处把形参槽实例化为具体源，跨 crate 应用摘要重建链路
   ▼
Finding（源→trait object 中转→sink→落点，带缺失的净化建议）→ SARIF / JSON
```

- **源识别不硬编码**：扫描 `impl ByteSource for X` 自动收集源类型，再按类型名语义
  归类 queue/frame/file。
- **trait object 擦除**：`take_one(source: &mut dyn ByteSource)` 的虚分派无函数体可
  摘要，引擎对未解析的接收者方法做保守污点透传，源信息不丢。
- **类型化方法解析**：`index.method_owners[方法][impl 所有者]` 让 `sink.load_x()` 只
  内联对应 impl 的方法，避免同名方法跨 crate 串味（这是大规模下误报爆炸的根因）。
- **守卫识别**：在 HIR 语句形态上识别「早返回 `if` + 终止块」，按 `len()/MAX_*`、
  `ALLOWED_*.contains`、`first()/CACHE_*`、`verify_signature/hmac` 分四类，记录被
  守卫的 Origin；同一 sink 前有有效守卫即判净化、不告警。
- **完整链路**：`Origin` 携带 `hops`（穿过的每个 `(函数, 调用点行号)`），因此不含
  sink 的中转函数 `take_one` 也能出现在 SARIF `codeFlows` 里。

## 3. 跨 crate 传播：函数摘要的粒度怎么选（核心权衡）

结论：**以「函数」为摘要单位，以「形参下标」为污点槽，上下文不敏感 + 过程内流敏感，
摘要只回答三个问题——返回值受哪些形参影响、函数体内有哪些 sink 效应、调了谁。**

| 粒度选项 | 召回 | 性能（20 万行） | 取舍 |
|---|---|---|---|
| 整 crate 一个摘要 / 只看「是否碰 bincode」布尔位 | 低：丢形参级来源，无法区分 queue/frame/file，也无法在调用点实例化 trait object | 最快 | 粒度过粗，源类型擦除后链路断裂 |
| **函数级 + 形参下标槽（本方案）** | **高：精确表达「返回值←第几个形参」，调用点用实参 Origin 绑定即可跨 crate 传播** | 每函数只算一次并缓存，亚线性 | 甜点 |
| 完全上下文敏感（每调用点一份摘要，对象敏感/路径敏感） | 略高 | 摘要数随调用点组合爆炸，20 万行不可行 | 收益不抵成本 |

为什么这个粒度兼顾性能与召回：

1. **摘要与调用上下文无关，可全局复用**。语料里每个 sink 方法只做一层
   `bincode::deserialize(raw)`，摘要只需记录「sink 的字节来自第 0 个形参」。任意
   调用点拿来后，用本次实参的 Origin 替换形参槽即可，不需要为每个调用点重算。
2. **trait object 在调用点实例化，而不是在摘要里猜**。`take_one` 的形参是
   `dyn ByteSource`，摘要里源是抽象的 `arg0`；到了入口 `handle_queue_*`，实参类型
   是 `MessageSource`，实例化阶段才把 `arg0` 绑成 `queue_message`。同一份摘要服务
   queue/frame/file 三种源，既不丢差异也不重复计算。
3. **流敏感只保留在过程内**。块内语句序、早返回守卫的作用域用一次线性 walk 解决；
   跨函数靠摘要拼接而不是内联展开，调用再深也是 O(边数) 的摘要应用，避免路径爆炸。
4. **守卫随摘要携带、在实例化时映射**。`*_checked` 的长度/白名单/tag/HMAC 守卫记录
   为受影响的形参 Origin，跨函数映射后仍能判定落点是否被净化，从而压掉 decoy 误报。

## 4. 增量与全量一致、性能

两层内容寻址缓存（键 = blake2b 内容哈希 + schema 版本）：

- `parse.json`：文件 → 函数 HIR 骨架。增量先用 `mtime+size` 快判，未变文件连
  tree-sitter 解析都跳过。
- `dataflow.json`：函数 → 过程内数据流摘要（纯数据，可 JSON 化）。
- `entry.json`：入口函数 body 哈希 → 源实例化后的 sink 效应。noop 时直接复用，
  连入口 walk 都跳过。

变更时按调用边求**反向闭包**（基于缓存摘要里的 CallRec，不碰 CST），只重解析/重算
受影响文件与其调用者；其余走缓存。最终告警始终由同一条入口实例化逻辑产出，因此
**增量与全量走同一套 HIR/摘要，结果一致**（输出不含时间戳，可字节级比对）。

### 实测（本机，合成语料与真实语料同构）

| 场景 | 规模 | 耗时 |
|---|---|---|
| 全量 | 22.9 万行 / 63 文件 / 4 万函数 | ~11–13 s（要求 <3 min） |
| 增量 noop | 同上 | ~10 s（要求 <15 s），0 文件重解析 |
| 增量改 1 个 sink crate | 同上 | ~16–17 s，仅重解析受闭包影响的 2 个文件 |
| 真实 50 样本全量 | 16 文件 / 133 函数 | 0.4 s |

单 crate 变更的最坏情况会把调用它的入口文件（巨型 `gen.rs`）正确卷入重算——这是
保守正确的依赖传播，不是浪费。

## 5. 指标与 CI

50 条标注样本：**召回 100%（≥85%）、误报率 0%（≤15%）**，22 个 checked decoy 全部
正确排除；每条告警带源→`take_one`→sink→落点的完整 `codeFlows` 与缺失净化建议。

CI 阻断新增（SARIF 为 error 级），例如 GitHub Actions：

```yaml
- run: python -m analyzer.cli --repo . --sarif bincode.sarif --incremental
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: bincode.sarif }
# 本地硬门禁（非零退出即失败）：
- run: python -m analyzer.cli --repo . | python -c "import sys,json;assert not json.load(sys.stdin)['findings']"
```

## 6. 模块

| 文件 | 职责 |
|---|---|
| `hir.py` | HIR 数据模型（FnSummary / Origin / Guard / SinkEffect）、类型名提取 |
| `index.py` | tree-sitter 解析、符号表、impl 归属、源类型发现、骨架序列化/并行 |
| `dataflow.py` | 过程内数据流、守卫识别、函数摘要构建/序列化、反向闭包 |
| `driver.py` | 入口识别、源实例化、链路重建、告警判定 |
| `entry_cache.py` / `cache.py` / `parse_cache.py` | 三层增量缓存 |
| `report.py` | SARIF 2.1.0（含 codeFlows）与 JSON 报告 |
| `cli.py` | 全量/增量编排 |
