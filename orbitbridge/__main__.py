"""命令行入口：本地批次采集和交接核对。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import audit, catalog, diagnostics, export, handoff, ingest, intake, protocol, quality, reconcile, recovery, store


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="orbitbridge", description="星地火情事件采集与交接网关")
    root.add_argument("--db", default="orbitbridge.sqlite3", help="SQLite 数据文件")
    commands = root.add_subparsers(dest="command", required=True)
    station = commands.add_parser("station-add", help="登记观测站")
    station.add_argument("station_id")
    station.add_argument("label")
    state = commands.add_parser("station-state", help="变更站点状态")
    state.add_argument("station_id")
    state.add_argument("state", choices=("active", "inactive"))
    subscription = commands.add_parser("subscribe", help="登记区域订阅")
    subscription.add_argument("subscription_id")
    subscription.add_argument("region")
    subscription.add_argument("--severity", type=int, default=1)
    subscription.add_argument("--confidence", default="0")
    substate = commands.add_parser("subscription-state", help="变更订阅状态")
    substate.add_argument("subscription_id")
    substate.add_argument("state", choices=("active", "inactive"))
    packet = commands.add_parser("ingest", help="导入单个观测包")
    packet.add_argument("packet")
    directory = commands.add_parser("ingest-dir", help="按文件名导入目录中的 JSONL")
    directory.add_argument("directory")
    directory.add_argument("--stop-on-error", action="store_true")
    queue = commands.add_parser("handoffs", help="查看交接队列")
    queue.add_argument("--subscription")
    queue.add_argument("--status", choices=("pending", "acknowledged"))
    queue.add_argument("--limit", type=int, default=100)
    queue.add_argument("--after", type=int, default=0)
    acknowledgement = commands.add_parser("ack", help="确认交接项")
    acknowledgement.add_argument("handoff_id", type=int)
    acknowledgement.add_argument("operator")
    batch = commands.add_parser("batch", help="查看批次来源")
    batch.add_argument("batch_id", type=int)
    observation = commands.add_parser("observation", help="查看观测来源")
    observation.add_argument("observation_id", type=int)
    quarantine = commands.add_parser("quarantine", help="查看隔离项")
    quarantine.add_argument("--station")
    summary = commands.add_parser("summary", help="计数和完整性核对")
    trace = commands.add_parser("trace", help="查看交接来源与活动")
    trace.add_argument("handoff_id", type=int)
    report = commands.add_parser("region-report", help="查看区域统计")
    report.add_argument("region")
    commands.add_parser("verify", help="检查数据库与来源链")
    station_plan = commands.add_parser("recovery-plan", help="查看站点目录恢复计划")
    station_plan.add_argument("station_id")
    station_plan.add_argument("directory")
    station_resume = commands.add_parser("recovery-resume", help="从已提交游标继续导入")
    station_resume.add_argument("station_id")
    station_resume.add_argument("directory")
    retry = commands.add_parser("quarantine-retry", help="重检已隔离的原始包")
    retry.add_argument("quarantine_id", type=int)
    retry.add_argument("packet")
    commands.add_parser("quality", help="检查跨表业务不变量")
    station_quality = commands.add_parser("station-quality", help="查看站点拒收原因")
    station_quality.add_argument("station_id")
    commands.add_parser("quarantine-quality", help="汇总隔离原因")
    packet_inspect = commands.add_parser("inspect-packet", help="预诊断单个观测包")
    packet_inspect.add_argument("packet")
    directory_inspect = commands.add_parser("inspect-dir", help="预诊断观测包目录")
    directory_inspect.add_argument("directory")
    commands.add_parser("reconcile", help="核对站点与订阅数量")
    batch_report = commands.add_parser("batch-report", help="核对单批次的观测与交接")
    batch_report.add_argument("batch_id", type=int)
    day_report = commands.add_parser("day-report", help="查看接收日期汇总")
    day_report.add_argument("day")
    manifest_check = commands.add_parser("manifest-check", help="预检批次清单")
    manifest_check.add_argument("manifest")
    manifest_check.add_argument("--strict", action="store_true")
    manifest_run = commands.add_parser("manifest-run", help="执行批次清单")
    manifest_run.add_argument("manifest")
    manifest_run.add_argument("--strict", action="store_true")
    handoff_export = commands.add_parser("export-handoffs", help="导出交接清单")
    handoff_export.add_argument("subscription_id")
    handoff_export.add_argument("destination")
    handoff_export.add_argument("--after", type=int, default=0)
    handoff_export.add_argument("--through", type=int)
    handoff_export.add_argument("--status", choices=("pending", "acknowledged"))
    export_check = commands.add_parser("export-check", help="校验导出文件")
    export_check.add_argument("path")
    export_check.add_argument("sha256")
    demo = commands.add_parser("demo", help="运行本地合成数据演示")
    demo.add_argument("--workspace", default="./demo-workspace")
    return root


def _demo(workspace: Path) -> dict[str, Any]:
    workspace.mkdir(parents=True, exist_ok=True)
    database = workspace / "demo.sqlite3"
    if database.exists():
        database.unlink()
    connection = store.open_database(database)
    try:
        catalog.register_station(connection, "sat-a", "合成观测站 A", when="2026-10-28T12:00:00Z")
        catalog.register_subscription(connection, "forest-watch", "forest-north", 3, "0.70",
                                      when="2026-10-28T12:00:00Z")
        records = [
            {"kind": "observation", "id": "sim-001", "observed_at": "2026-10-28T12:00:00Z",
             "region": "forest-north", "latitude": 31.20, "longitude": 121.45, "confidence": "0.88",
             "severity": 4, "source": "infrared"},
            {"kind": "observation", "id": "sim-002", "observed_at": "2026-10-28T12:01:00Z",
             "region": "forest-north", "latitude": 31.21, "longitude": 121.46, "confidence": "0.55",
             "severity": 2, "source": "thermal"},
        ]
        packet = protocol.encode_packet("sat-a", 1, "2026-10-28T12:02:00Z", records)
        source = workspace / "synthetic-packet.jsonl"
        source.write_bytes(packet)
        accepted = ingest.ingest_file(connection, source, when="2026-10-28T12:03:00Z")
        duplicate = ingest.ingest_file(connection, source, when="2026-10-28T12:03:01Z")
        queue = handoff.list_handoffs(connection)
        if len(queue) != 1 or accepted.handoff_count != 1 or duplicate.status != "duplicate":
            raise RuntimeError("合成演示结果与交接预期不符")
        ack = handoff.acknowledge(connection, queue[0]["handoff_id"], "值守员甲",
                                  when="2026-10-28T12:04:00Z")
        trace = audit.handoff_trace(connection, queue[0]["handoff_id"])
        issues = audit.verify_lineage(connection)
        if issues or trace["handoff"]["batch_id"] != accepted.batch_id:
            raise RuntimeError(f"合成演示来源链不一致：{issues}")
        return {"accepted": accepted.as_dict(), "duplicate": duplicate.as_dict(),
                "handoff": ack, "counts": store.counts(connection), "integrity_issues": issues}
    finally:
        connection.close()


def dispatch(args: argparse.Namespace) -> Any:
    if args.command == "demo":
        return _demo(Path(args.workspace))
    connection = store.open_database(args.db)
    try:
        if args.command == "station-add":
            return catalog.register_station(connection, args.station_id, args.label)
        if args.command == "station-state":
            return catalog.set_station_active(connection, args.station_id, args.state == "active")
        if args.command == "subscribe":
            return catalog.register_subscription(connection, args.subscription_id, args.region,
                                                 args.severity, args.confidence)
        if args.command == "subscription-state":
            return catalog.set_subscription_active(connection, args.subscription_id, args.state == "active")
        if args.command == "ingest":
            return ingest.ingest_file(connection, args.packet).as_dict()
        if args.command == "ingest-dir":
            return ingest.ingest_directory(connection, args.directory, stop_on_error=args.stop_on_error)
        if args.command == "handoffs":
            return handoff.list_handoffs(connection, subscription_id=args.subscription, status=args.status,
                                         limit=args.limit, after_id=args.after)
        if args.command == "ack":
            return handoff.acknowledge(connection, args.handoff_id, args.operator)
        if args.command == "batch":
            return audit.batch_detail(connection, args.batch_id)
        if args.command == "observation":
            return audit.observation_detail(connection, args.observation_id)
        if args.command == "quarantine":
            return audit.list_quarantine(connection, station_id=args.station)
        if args.command == "summary":
            return audit.summary(connection)
        if args.command == "trace":
            return audit.handoff_trace(connection, args.handoff_id)
        if args.command == "region-report":
            return audit.region_report(connection, args.region)
        if args.command == "verify":
            issues = audit.verify_lineage(connection)
            return {"ok": not issues, "issues": issues}
        if args.command == "recovery-plan":
            return recovery.plan_station(connection, args.station_id, args.directory)
        if args.command == "recovery-resume":
            return recovery.resume_station(connection, args.station_id, args.directory)
        if args.command == "quarantine-retry":
            return recovery.retry_file(connection, args.quarantine_id, args.packet)
        if args.command == "quality":
            return quality.check_all(connection)
        if args.command == "station-quality":
            return quality.station_quality(connection, args.station_id)
        if args.command == "quarantine-quality":
            return quality.quarantine_quality(connection)
        if args.command == "inspect-packet":
            return diagnostics.inspect_packet(connection, args.packet)
        if args.command == "inspect-dir":
            return diagnostics.inspect_directory(connection, args.directory)
        if args.command == "reconcile":
            return reconcile.full_reconciliation(connection)
        if args.command == "batch-report":
            return reconcile.batch_counts(connection, args.batch_id)
        if args.command == "day-report":
            return reconcile.day_counts(connection, args.day)
        if args.command == "manifest-check":
            return intake.preflight(connection, args.manifest, strict=args.strict)
        if args.command == "manifest-run":
            return intake.execute_manifest(connection, args.manifest, strict=args.strict)
        if args.command == "export-handoffs":
            return export.export_handoffs(connection, args.subscription_id, args.destination,
                                          start_id=args.after, end_id=args.through, status=args.status).as_dict()
        if args.command == "export-check":
            return export.verify_export(args.path, args.sha256)
        raise RuntimeError("未知命令")
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = dispatch(args)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        if args.command in {"verify", "quality", "reconcile"} and not result["ok"]:
            return 2
        return 0
    except (catalog.CatalogError, handoff.HandoffError, ingest.IngestError, audit.AuditError, recovery.RecoveryError,
            intake.ManifestError, export.ExportError, reconcile.ReconcileError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "error"), "message": str(exc),
                          "quarantine_id": getattr(exc, "quarantine_id", None)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
