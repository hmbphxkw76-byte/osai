"""S3.7: REST API 服务化 — 通过 FastAPI 暴露 pipeline 能力

对齐 L5：顶级红队平台需提供 API 接口供 CI/CD 集成、自动化调度、
远程触发扫描。本模块将 pipeline 的核心能力封装为 RESTful API。

启动方式:
    uvicorn pipeline.api:app --host 0.0.0.0 --port 8765

API 端点:
    POST   /api/v1/scan          — 启动单目标扫描
    POST   /api/v1/scan/batch    — 启动批量扫描
    GET    /api/v1/scan/{run_id} — 查询扫描状态
    GET    /api/v1/report/{run_id} — 获取分析结果
    GET    /api/v1/report/{run_id}/html — 获取 HTML 报告
    GET    /api/v1/health        — 健康检查
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# R5: API Key 鉴权 — 从环境变量读取，未设置时为 dev 模式（不鉴权）
_API_KEY_ENV = "GARAK_PIPELINE_API_KEY"


def _get_configured_api_key() -> str | None:
    """读取已配置的 API Key（环境变量或 .env）

    :returns: API Key 字符串；未配置返回 None（dev 模式）
    """
    return os.environ.get(_API_KEY_ENV) or None


def _verify_api_key(provided_key: str | None) -> bool:
    """验证 API Key（恒定时间比较，防止时序攻击）

    :param provided_key: 请求中提供的 key
    :returns: True=验证通过；False=验证失败
    """
    expected = _get_configured_api_key()
    if not expected:
        # dev 模式：未配置 API Key，允许所有请求
        return True
    if not provided_key:
        return False
    return hmac.compare_digest(expected, provided_key)

# FastAPI app（惰性导入，避免未安装时 pipeline 其他模块不可用）
try:
    from fastapi import BackgroundTasks, FastAPI, HTTPException

    app = FastAPI(
        title="garak-pipeline API",
        description="LLM 安全扫描流水线 REST API — 基于 garak 0.15.1 二次开发",
        version="1.1.0",
    )

    # R5: API Key 鉴权中间件
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    @app.middleware("http")
    async def api_key_auth_middleware(request: Request, call_next):
        """R5: API Key 鉴权中间件

        - /api/v1/health 始终放行（健康检查不需要鉴权）
        - /docs, /openapi.json, /redoc 始终放行（Swagger UI）
        - 其余 /api/v1/ 请求需携带 X-API-Key header
        - 未配置 GARAK_PIPELINE_API_KEY 时为 dev 模式（不鉴权）
        """
        path = request.url.path
        # 健康检查和文档端点不需要鉴权
        if path in ("/api/v1/health", "/docs", "/openapi.json", "/redoc") or not path.startswith("/api/v1/"):
            return await call_next(request)

        provided_key = request.headers.get("X-API-Key")
        if not _verify_api_key(provided_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "无效或缺失的 API Key。请在 X-API-Key header 中提供有效的 key。"},
            )
        return await call_next(request)

    if not _get_configured_api_key():
        logger.warning("R5: API 鉴权未启用（dev 模式）。设置 %s 环境变量以启用鉴权。", _API_KEY_ENV)
except ImportError:
    app = None  # type: ignore[assignment]
    logger.debug("FastAPI 不可用，API 模块未激活")


# ---------------------------------------------------------------------------
# 请求/响应模型
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    """扫描请求"""

    endpoint: str = Field(..., description="目标 LLM 端点 URL")
    model: str = Field(..., description="目标模型名")
    api_key: str | None = Field(None, description="API key（可选，Cookie 认证可省略）")
    mode: str = Field("standard", description="扫描模式: standard/full/balanced/quick/smoke")
    artifacts_dir: str = Field("outputs", description="产物目录")
    config: dict[str, Any] | None = Field(None, description="额外配置覆盖")


class BatchScanRequest(BaseModel):
    """批量扫描请求"""

    config_path: str = Field(..., description="target_list.yaml 路径")
    project_root: str = Field(".", description="项目根目录")


class ScanResponse(BaseModel):
    """扫描启动响应"""

    run_id: str
    status: str = "accepted"
    message: str = "扫描已启动"


# ---------------------------------------------------------------------------
# P2-2: SQLite 持久化后端（替代内存 dict，支持进程重启后任务状态不丢失）
# ---------------------------------------------------------------------------
import sqlite3
import threading

_DB_PATH = Path("outputs") / ".scan_tasks.db"
_db_lock = threading.Lock()


def _init_db(db_path: Path | None = None) -> sqlite3.Connection:
    """初始化 SQLite 数据库，返回连接"""
    path = db_path or _DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_tasks (
            run_id     TEXT PRIMARY KEY,
            status     TEXT NOT NULL DEFAULT 'pending',
            target     TEXT,
            mode       TEXT,
            artifacts_dir TEXT,
            config_path TEXT,
            task_type  TEXT DEFAULT 'single',
            error      TEXT,
            result     TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


# 兼容层：保留 _scan_tasks 的 dict 接口，底层透明切换到 SQLite
class _ScanTaskStore:
    """SQLite-backed scan task store with dict-like interface"""

    def __init__(self):
        self._conn = _init_db()

    def _now(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()

    def __contains__(self, run_id: str) -> bool:
        with _db_lock:
            cur = self._conn.execute("SELECT 1 FROM scan_tasks WHERE run_id=?", (run_id,))
            return cur.fetchone() is not None

    def __getitem__(self, run_id: str) -> dict:
        with _db_lock:
            cur = self._conn.execute("SELECT * FROM scan_tasks WHERE run_id=?", (run_id,))
            row = cur.fetchone()
        if row is None:
            raise KeyError(run_id)
        cols = [d[0] for d in cur.description]
        item = dict(zip(cols, row))
        # 反序列化 result
        if item.get("result"):
            try:
                item["result"] = json.loads(item["result"])
            except (json.JSONDecodeError, TypeError):
                pass
        if item.get("target"):
            try:
                item["target"] = json.loads(item["target"])
            except (json.JSONDecodeError, TypeError):
                pass
        return item

    def __setitem__(self, run_id: str, value: dict) -> None:
        now = self._now()
        target_json = json.dumps(value.get("target"), ensure_ascii=False) if value.get("target") else None
        result_json = json.dumps(value.get("result"), ensure_ascii=False) if value.get("result") else None
        with _db_lock:
            self._conn.execute("""
                INSERT INTO scan_tasks (run_id, status, target, mode, artifacts_dir, config_path, task_type, error, result, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    target=excluded.target,
                    error=excluded.error,
                    result=excluded.result,
                    updated_at=excluded.updated_at
            """, (
                run_id,
                value.get("status", "pending"),
                target_json,
                value.get("mode"),
                value.get("artifacts_dir"),
                value.get("config_path"),
                value.get("task_type", "single"),
                value.get("error"),
                result_json,
                now,
                now,
            ))
            self._conn.commit()

    def values(self) -> list[dict]:
        with _db_lock:
            cur = self._conn.execute("SELECT * FROM scan_tasks")
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
        items = []
        for row in rows:
            item = dict(zip(cols, row))
            if item.get("result"):
                try:
                    item["result"] = json.loads(item["result"])
                except (json.JSONDecodeError, TypeError):
                    pass
            items.append(item)
        return items


_scan_tasks = _ScanTaskStore()


def _run_scan_task(
    run_id: str,
    target: dict,
    mode: str,
    artifacts_dir: str,
    config: dict | None,
) -> None:
    """后台扫描任务（在 BackgroundTasks 中执行）"""
    try:
        _scan_tasks[run_id]["status"] = "running"
        from pipeline.runner import PipelineRunner

        runner = PipelineRunner(
            target=target,
            mode=mode,
            artifacts_dir=artifacts_dir,
            config=config or {},
            run_id=run_id,
        )
        runner.run(stages="all")
        _scan_tasks[run_id]["status"] = "completed"
        _scan_tasks[run_id]["result"] = runner.get_results()
    except Exception as exc:
        _scan_tasks[run_id]["status"] = "failed"
        _scan_tasks[run_id]["error"] = str(exc)
        logger.exception("扫描任务 %s 失败", run_id)


# ---------------------------------------------------------------------------
# API 端点
# ---------------------------------------------------------------------------
if app is not None:

    @app.get("/api/v1/health")
    async def health_check():
        """健康检查"""
        try:
            import garak

            garak_version = garak.__version__
        except Exception:
            garak_version = "unknown"
        return {
            "status": "healthy",
            "garak_version": garak_version,
            "active_scans": sum(
                1 for t in _scan_tasks.values() if t["status"] == "running"
            ),
        }

    @app.post("/api/v1/scan", response_model=ScanResponse)
    async def start_scan(
        req: ScanRequest,
        background_tasks: BackgroundTasks,
    ):
        """启动单目标扫描"""
        run_id = f"api_{uuid.uuid4().hex[:12]}"
        target = {
            "endpoint": req.endpoint,
            "model": req.model,
            "api_key": req.api_key or "",
        }
        _scan_tasks[run_id] = {
            "status": "pending",
            "target": target,
            "mode": req.mode,
            "artifacts_dir": req.artifacts_dir,
        }
        background_tasks.add_task(
            _run_scan_task,
            run_id,
            target,
            req.mode,
            req.artifacts_dir,
            req.config,
        )
        return ScanResponse(run_id=run_id, message="扫描已启动")

    @app.post("/api/v1/scan/batch")
    async def start_batch_scan(
        req: BatchScanRequest,
        background_tasks: BackgroundTasks,
    ):
        """启动批量扫描"""
        run_id = f"batch_{uuid.uuid4().hex[:12]}"
        _scan_tasks[run_id] = {
            "status": "pending",
            "type": "batch",
            "config_path": req.config_path,
        }

        def _run_batch():
            try:
                _scan_tasks[run_id]["status"] = "running"
                from pipeline.batch_runner import run_batch

                summary = run_batch(req.config_path, req.project_root)
                _scan_tasks[run_id]["status"] = "completed"
                _scan_tasks[run_id]["result"] = summary
            except Exception as exc:
                _scan_tasks[run_id]["status"] = "failed"
                _scan_tasks[run_id]["error"] = str(exc)

        background_tasks.add_task(_run_batch)
        return ScanResponse(run_id=run_id, message="批量扫描已启动")

    @app.get("/api/v1/scan/{run_id}")
    async def get_scan_status(run_id: str):
        """查询扫描状态"""
        if run_id not in _scan_tasks:
            raise HTTPException(status_code=404, detail="扫描任务不存在")
        task = _scan_tasks[run_id]
        return {
            "run_id": run_id,
            "status": task["status"],
            "error": task.get("error"),
            "result": task.get("result"),
        }

    @app.get("/api/v1/report/{run_id}")
    async def get_report(run_id: str, artifacts_dir: str = "outputs"):
        """获取分析结果 JSON"""
        analysis_path = Path(artifacts_dir) / "04_analysis" / f"analysis_{run_id}.json"
        if not analysis_path.exists():
            raise HTTPException(status_code=404, detail="分析结果不存在")
        with open(analysis_path, encoding="utf-8") as f:
            return json.load(f)

    @app.get("/api/v1/report/{run_id}/html")
    async def get_html_report(run_id: str, artifacts_dir: str = "outputs"):
        """获取 HTML 报告"""
        html_path = Path(artifacts_dir) / "05_export" / f"report_{run_id}.html"
        if not html_path.exists():
            raise HTTPException(status_code=404, detail="HTML 报告不存在")
        from fastapi.responses import HTMLResponse

        with open(html_path, encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    @app.get("/api/v1/report/{run_id}/avid")
    async def get_avid_report(run_id: str, artifacts_dir: str = "outputs"):
        """获取 AVID 格式报告"""
        avid_path = Path(artifacts_dir) / "05_export" / f"avid_{run_id}.json"
        if not avid_path.exists():
            raise HTTPException(status_code=404, detail="AVID 报告不存在")
        with open(avid_path, encoding="utf-8") as f:
            return json.load(f)

    @app.get("/api/v1/report/{run_id}/pdf")
    async def get_pdf_report(run_id: str, artifacts_dir: str = "outputs"):
        """获取 PDF 报告"""
        pdf_path = Path(artifacts_dir) / "05_export" / f"report_{run_id}.pdf"
        if not pdf_path.exists():
            raise HTTPException(status_code=404, detail="PDF 报告不存在")
        from fastapi.responses import FileResponse

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"report_{run_id}.pdf",
        )
