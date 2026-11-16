# 星地火情事件采集与交接网关

本项目供区域应急数据值守人员处理上游已经筛选的候选火情事件。输入为本地 JSONL 观测包；它不处理遥感影像，也不判断真实火情。仓库演示数据均为合成数据。

## 运行

使用 Python 3.11 或更新版本，无第三方依赖。先在项目根目录运行 `python -m orbitbridge demo --workspace /tmp/orbitbridge-demo`，可看到接收、重复导入、交接确认和来源核对结果。演示会重建指定目录中的 `demo.sqlite3`；请仅使用专门的演示目录。

真实本地包的命令顺序为：

```text
python -m orbitbridge --db work.sqlite3 station-add sat-a "站点 A"
python -m orbitbridge --db work.sqlite3 subscribe north-watch forest-north --severity 3 --confidence 0.7
python -m orbitbridge --db work.sqlite3 ingest packet.jsonl
python -m orbitbridge --db work.sqlite3 handoffs --status pending
python -m orbitbridge --db work.sqlite3 ack 1 "值守员甲"
python -m orbitbridge --db work.sqlite3 trace 1
python -m orbitbridge --db work.sqlite3 verify
```

包第一行为 `kind=packet`、`schema=1`、`station_id`、正整数 `sequence`、带时区 `created_at`、`record_count`、`digest`。后续每行是 `kind=observation`，包含 `id`、带时区 `observed_at`、`region`、`latitude`、`longitude`、`confidence`、1–5 的 `severity` 和 `source`。`source` 可为 `infrared`、`optical`、`thermal`。摘要是每条记录按键排序、紧凑 UTF-8 JSON 表示后追加换行的 SHA-256。可参考 `orbitbridge.protocol.encode_packet` 生成测试包。

同站点序号须连续。相同包重放返回 `duplicate`，相同序号不同内容或跳号进入隔离记录。所有观测和交接项在一个 SQLite 事务中提交；无匹配订阅的观测仍被保存。订阅规则只影响后续提交的包。`verify` 检查数据库、游标、批次数与交接来源。

可用 `inspect-packet` 或 `inspect-dir` 在不改数据库的情况下诊断待收件文件。目录中存在跳号时，先用 `recovery-plan sat-a incoming/` 查看可连续提交的包，再用 `recovery-resume sat-a incoming/` 按站点序号接收。`quarantine-retry <编号> <原文件>` 只允许重检与隔离记录身份一致的包。

清单是 UTF-8 JSON，含 schema、name 和 packets 数组；每个条目含 file、station_id、sequence 和文件 SHA-256。清单与包放在同一目录。`manifest-check <清单>` 预检摘要、包身份和游标，`manifest-run <清单>` 执行可连续提交的条目。执行时再次核对文件摘要。

`quality` 检查跨表不变量，`reconcile` 核对站点和订阅数量。`batch-report <编号>` 与 `day-report YYYY-MM-DD` 分别提供批次及日期统计。`export-handoffs <订阅编号> <新文件路径>` 导出交接来源并返回摘要，`export-check <文件路径> <摘要>` 校验文件。导出不会覆盖已有文件。

## 交付版本与外部回执

外部应急部门把交接回执作为离线文件送回时，回执核对的是"哪一份清单"和"哪一次责任安排"，不能按交接号直接销账。

1. `receiver-add <接收方编号> <名称>` 登记外部接收方；之后可用 `receiver-state` 停用。
2. `export-delivery <订阅编号> <文件路径> [--after N] [--through N] [--status ...] [--receiver 编号]` 写出可核验的交付版本：正文文件旁同时生成 `<文件>.delivery.json` 描述文件，包含 `delivery_key`、订阅、窗口、正文 SHA-256，以及逐项 `handoff_id`、观测指纹、交付时的责任修订和状态。交付先登记为 `prepared`。
3. `delivery-register <delivery_key>` 完成交付登记，登记后才接受回执核对。若文件已写出但登记未完成（例如进程中断），用 `delivery-recover <文件路径>` 从磁盘描述文件恢复；恢复时重新核对正文摘要、描述摘要与逐项指纹，内容不符会拒绝，不会重新导出另一内容冒充原版。
4. `delivery-verify <delivery_key>` 重新核对正文摘要、描述摘要与逐项覆盖；`deliveries` 列出交付版本。

回执文件为 UTF-8 JSON，字段固定为 `kind=handoff-receipt`、`schema=1`、`receipt_id`、`receiver_id`、`delivery_key`、带时区 `received_at` 和 `items`；每个条目包含 `handoff_id`、`observation_fingerprint` 和 `result`（`received` 或 `not_received`）。

接收方式：`receipt-submit <文件>` 单件收件，`receipt-dir <目录>` 按目录收件，或 `receipt-manifest-check <清单>` / `receipt-manifest-run <清单>` 按回执清单（`kind=handoff-receipts`、`schema=1`、`name`、`receipts` 数组，每项含 `file` 与 `sha256`）预检并执行。无法解析的回执进入回执隔离，用 `receipt-quarantine` 查看、`receipt-retry <隔离编号> <原文件>` 重试，重试文件必须与隔离内容一致。

核对结果：

- `pending`（待核）：接收方未登记或已停用、缺少对应交付版本、交付登记未完成。补齐后用 `receipt-recheck [回执编号]` 重新验证接收方身份、交付摘要和逐项覆盖。
- `verified`（已核）：回执引用的交付版本完整、逐项覆盖成立、观测指纹一致，并在 `receipt_items` 中逐项给出判定。
- `disputed`（争议）：接收方与交付对象不符、交付摘要被改、回执时间不合理、逐项覆盖缺失/多余/指纹不符，或同一接收方同一 `receipt_id` 换了内容。争议保留首次内容与理由，不解除责任。

相同接收方、相同 `receipt_id`、相同内容的重送只累加尝试次数，不重复解除责任；同一身份换内容时保留首份并记录 `receipt_conflicts` 冲突。

## 责任安排

责任与外部回执是两条证据链。`reassign <交接编号> <责任人|岗位> [--reason ...]` 改派责任并生成新的责任修订；`responsibilities` 查看当前责任；`ack` 记录本地处置完成。

回执只在逐项判定时冻结当时依据：若交付后发生改派，晚到回执只能证明原交付的接收情况，判定为 `retained / responsibility_changed`，当前责任保持给新责任人；若本地已确认处置，判定为 `retained / locally_acknowledged`。只有交付后责任修订未变且状态仍为 `open` 的条目，回执才能解除责任（`released_external`）。`trace <交接编号>` 同时显示本地交接状态、外部回执、待核/争议回执和责任状态；`receipt-trace <回执编号>` 显示单条回执的判定理由与活动。

测试：`python -m unittest discover -s tests -v`。语法检查：`python -m compileall -q orbitbridge`。
