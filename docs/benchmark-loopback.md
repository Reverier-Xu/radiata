# Loopback 基准：裸 TLS 1.3 vs radiata 完整通道

> 2026-09-10，release 构建，本地回环（网络良好环境的理想上界）。
> 复现：`cargo test --release --test latency_benchmark -- --ignored --nocapture`
> 基准代码：`tests/latency_benchmark.rs`（默认 `#[ignore]`，显式运行）。

## 结果（单机，12 代酷睿级别桌面，tokio multi-thread ×4）

| 指标 | 裸 TLS 1.3（rustls + TCP） | radiata 完整通道 | 开销倍数 |
| --- | --- | --- | --- |
| 建立连接 | 握手 p50 **317 µs** | 完整合并 p50 ~**203 ms**（单样本） | ~640×（一次性） |
| 同步往返（1 KiB） | echo p50 **7.5 µs**（mean 7.9） | `send_sync` 准入 ack p50 **34.9 µs**（mean 60.6） | **~4.7×** |
| 端到端送达（1 KiB，radiata only） | — | p50 **53.5 µs**（mean 87.1） | — |
| 可持续吞吐（32 KiB 块） | **4810 MiB/s** | **426 MiB/s**（32×1 MiB 流） | **~11.3×**（即 8.8% 效率） |

## 测量口径

- **同步往返**：裸 TLS = 写 1 KiB → 读回显；radiata = `open_stream` + `send_sync`（单块）→ 目的地当前进程准入 ack。两者都是各自协议机制下的一次线上往返；radiata 侧额外包含 CBOR 帧编解码、open 信封验证、入站表准入。
- **端到端送达**：radiata 特有——发送瞬间到接收方 `PacketConsumer` 收到完整流的时刻（含 ack 往返 + body 传输 + 消费者投递）。
- **吞吐**：32 MiB，32 KiB 块（线上块上限），端到端（接收方计满为止）。radiata 按其流控语义用 32 条顺序 1 MiB 流测量（见下）。
- **建立连接**：裸 TLS = 单次 1-RTT 握手；radiata = 完整 join（TLS + WebSocket 升级 + 五位置认证交换 + 凭据准入 + 描述符收敛等待），含重试轮询，非纯握手成本。

## 两个结构性发现

1. **单流突发上限 = 会话队列窗口（默认 8 MiB，`NodeConfig::with_session_queue_limits` 可调）**。数据面对源头 chunk 无阻塞背压：队列满时 `send` 返回 `Overloaded`，泵将该流以 `StreamInterrupted` 终止（文档化的"显式中断、永不重放"语义）。因此**单条流一次性突发超过队列窗口必被截断**——这不是缺陷而是流控设计，但调用方（以及吞吐基准）必须按"多条流、每条 ≤ 窗口"的方式发送。上表 radiata 吞吐即按此口径（可持续吞吐）。
2. **同步开销 ~35 µs 的构成**：一次往返 = 两侧各一次 CBOR 规范编解码 + 帧校验 + 准入表操作 + TLS 记录封装。p50 35 µs 对回环是健康数字；真实网络（LAN RTT 100 µs–1 ms）下该封装开销将被网络 RTT 掩盖，占比降到 3%–35%。

## 结论

- 回环理想条件下，radiata 通道的同步往返时延为裸 TLS 的 **~4.7 倍**（35 µs vs 7.5 µs，p50），绝对值远低于任何真实网络 RTT——**在真实部署中时延由物理网络主导，通道封装可忽略**。
- 可持续吞吐为裸 TLS 的 **~9%**（426 vs 4810 MiB/s）。元数据同步（本 crate 的主要负载：描述符/信任/资源记录）单轮载荷为 KiB 量级、默认 250 ms 一个反熵节拍，426 MiB/s 比需求高四个数量级；需要大吞吐数据面的应用应使用更大的块或应用层合帧。
- 建连成本 203 ms 是 join 一次性成本（含收敛等待），与长连接会话的稳态性能无关。
