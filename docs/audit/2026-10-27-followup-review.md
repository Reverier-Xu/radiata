# 遗留项复核与后续规划（2026-10-27）

## 复核方法

对 [2026-10-23-aggregated-followups.md](2026-10-23-aggregated-followups.md) 登记的
全部暂缓/遗留条目，在当前 `main`（与 `origin/main` 完全同步）上逐条复核代码证据。
复核采用编排方直接阅读 + 两个独立子代理（glm-5.3，只读）交叉互证；上一轮的
30 个修复提交亦逐个验证真实存在于 git 历史中。

**总结论：文档登记与代码现状零漂移。** 暂缓条目无一自愈、无一失真；
14 个遗留条目经维护者逐条确认，2 个决策项已裁决。

## 维护者裁决记录（本轮新增）

| 条目 | 裁决 |
| --- | --- |
| A7 预算矩阵 | **改注释**：把矩阵表述精确化为实际 6 格，不补 cell |
| A10 严格 SLO | **保持 operator-run**，收紧文档措辞（常规绿 CI ≠ SLO 证据），不加 CI strict job |
| C1 D-6 origin 首跳探索 | **库内不做**。契约：本库不保障消息 1:1 投递，首跳选错由业务方重发恢复；需文档化 |
| C2 P1-3/A11 key 并发创建 | **维持忽略**（上一轮裁决），关闭 |

## 确认结论总表

### A. 测试/证据强化（暂缓类）

Wave 1 已落地的条目移至文末"已修复记录"。

| # | 条目 | verdict | 关键证据（当前代码） | 处置 |
| --- | --- | --- | --- | --- |
| A3 | 握手重放测试 | still-open | `src/protocol/handshake.rs:1685-1689` 靠位置序号 OutOfOrder 在签名工作之前拒绝；exporter/nonce 绑定的签名层防御从未被执行 | Wave 2：推进到合法 proof 位置再投重放材料 |
| A5 | 分区/重复断言 | still-open | `tests/membership_sync.rs:675-703` 先 dedup 后计数（"N 条并行会话"断言为死代码）；partition 用例只断一条边，`wait_connected` 测的是从未断开的既有边 | Wave 2：dedup 前观测多重性 + 真分量 split |
| A6 | 零传输证明 | still-open | `src/resource/page.rs:516-536` 只断言零安装，页面仍全量 emit，无字节/分配测量；`e2e.rs` 同 | Wave 2：emit 侧字节计数 |
| A8 | 仿真≠运行时 | partial | 模型本质不变（`network.rs` 字节记账/boot epoch）；证据已经 `ProducerKind::Simulation`（`test-support/src/lib.rs:364-372`）显式分类 | Wave 3：runtime 恢复证据通道（建设项） |
| A9 | 参考 oracle 不独立 | still-open | `src/storage/contract/reference.rs:160,300` 直接调用生产共享的 `classify_receipt`/`commit_precheck`（`src/provider.rs:968,1012`），语义漂移时 oracle 与生产同步变化 | Wave 3：独立化判定语义或加变异测试 |
| A10 | 严格 SLO 无 CI 强制 | still-open | `RADIATA_SLO_PROFILE_STRICT` 在 `.github/workflows/` 出现 0 次；`scripts/verify-release.sh:27-31` 自认 operator-run | Wave 3：**收紧文档措辞**（维护者裁决） |

### B. 已知遗留行为项

| # | 条目 | verdict | 关键证据（当前代码） | 处置 |
| --- | --- | --- | --- | --- |
| B2 | `MemberSpkiTable` 界非旋钮 | still-open | `src/session/driver.rs:137-139` 私有常量 4/256；`NodeConfig`（`src/config.rs:9-49`）无对应字段 | Wave 3：加 `NodeConfig` 旋钮 |
| B3 | redb flake ×2 | still-open | 锁释放竞态（`tests/redb_runtime.rs:123-131` 局部重试缓解，机制未根治）；`cluster_gate` 每文件独立，跨文件集群并行无全局串行 | Wave 3：根治竞态 + 并行度治理 |
| B4 | `ADMISSION_CONCURRENCY` 未联合调参 | still-open | `src/runtime/supervisor.rs:65` 硬编码 4，仅 `PUMP_HANDOFF_CAPACITY` 派生，与其他容量旋钮无配比 | Wave 3：联合调参 |

### C. 已关闭

| 条目 | 关闭理由 |
| --- | --- |
| C1 D-6 origin 首跳探索 | 维护者裁决：库内不做，契约文档化（见下） |
| C2 P1-3/A11 key 并发创建 | 维持忽略裁决 |
| admission_runtime deadline 契约 | 上轮已随 P2-15 更新（维护者批准） |

## 后续工作波次

**Wave 1（已完成，2026-10-27）**：见文末"已修复记录"。

**Wave 2（测试场景重建）**

1. A3：重放测试推进到合法 proof 位置，断言签名/transcript 层失败。
2. A5：dedup 前观测会话多重性；构造真分量 split + 离线写入 + 自动重连 +
   快照一致断言。
3. A6：emit 侧统计页面字节数，把"零传输"从"零安装"升级为可测量断言。

**Wave 3（决策已落定后的工程项）**

4. A8：runtime 恢复证据通道（真实节点 + 受控传输 + 持久化重开）。
5. A9：oracle 判定语义独立化或变异测试。
6. A10：文档收紧——明确常规绿 CI 不构成 SLO 证据，SLO 为 operator-run。
7. B2：`MemberSpkiTable` 上界接入 `NodeConfig`。
8. B3：redb 锁释放竞态根治 + 跨文件集群并行度治理。
9. B4：`ADMISSION_CONCURRENCY` 与其他容量旋钮联合调参。

每项遵循"一个逻辑改动一个 commit + 全量质量门"；行为改动须附表达可观测
失败的回归测试。

## 已修复记录（2026-10-27，Wave 1）

四条并行 writer lane（glm-5.3，独立 worktree），编排方逐 diff 复核后集成；
合并后主线全量质量门通过（fmt/taplo/check/clippy -D warnings/全量测试
41 个二进制 1075 项全绿）。

| 条目 | 修复提交 | 方案要点 |
| --- | --- | --- |
| A1 golden witness 自比较 | `75df509` | owner 模块持有唯一冻结字面量（`pub(crate)` `cfg(test)`），manifest 直接引用；删除恒真自比较循环。意外发现：manifest 的 pending 向量与 owner golden 本就不同形（漂移实证），以 `PENDING_RECORD_COMPAT_GOLDEN` 单列 |
| A2 命名空间守卫 | `c6f4d81` | 逐处定位代替集合相等；literal 必须出现在 `*_NAMESPACE` 常量声明上；扫描覆盖 src/tests/examples/fuzz/test-support；新增常量↔registry 双向相等断言 |
| A4 快照 roundtrip | `d0761e0` | 补 `decode_store` + 全量相等断言 + 首/中/尾 binding 抽查 |
| A7 预算矩阵注释 | `1bcd284` | 注释精确化为实际 6/9 cell，注明未覆盖形态与时长取舍 |
| B1 SessionChanged 奇偶性 | `ebb9a9c` | sync 吊销路径补发 `SessionChanged`（先 SessionChanged 后 NodeRevoked，镜像本地路径）；回归测试经变异验证 |
| C1 投递契约文档化 | `d035c81` | guide 路由章节 + `derive_return_stream_with_hops` rustdoc：尽力投递、首跳无库内恢复、调用方幂等重发 |
