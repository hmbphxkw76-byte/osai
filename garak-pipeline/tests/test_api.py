"""P4-3: tests/test_api.py — REST API 测试覆盖

验证 P2-2 SQLite 持久化后端和 API 端点：
- _ScanTaskStore 的 dict 接口（__contains__/__getitem__/__setitem__/values）
- SQLite 持久化（进程重启后状态不丢失）
- FastAPI 端点基本可用性（health/scan/report）
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def _cleanup_db(path):
    """安全删除 SQLite db 文件（Windows 上可能需要多次尝试）"""
    try:
        if os.path.exists(path):
            os.remove(path)
    except PermissionError:
        pass  # Windows 上 SQLite 句柄可能未释放，忽略


class TestScanTaskStore:
    """P2-2: SQLite 持久化后端测试"""

    def test_set_and_get(self, tmp_path):
        """写入任务后应能读取"""
        from pipeline.api import _ScanTaskStore, _init_db
        db_path = tmp_path / "test_set_get.db"
        store = _ScanTaskStore.__new__(_ScanTaskStore)
        store._conn = _init_db(db_path)
        store["test_run_1"] = {"status": "pending", "target": {"endpoint": "http://test"}}
        assert "test_run_1" in store
        item = store["test_run_1"]
        assert item["status"] == "pending"
        store._conn.close()

    def test_update_existing(self, tmp_path):
        """更新已有任务状态"""
        from pipeline.api import _ScanTaskStore, _init_db
        db_path = tmp_path / "test_update.db"
        store = _ScanTaskStore.__new__(_ScanTaskStore)
        store._conn = _init_db(db_path)
        store["run_1"] = {"status": "pending"}
        store["run_1"] = {"status": "running"}
        item = store["run_1"]
        assert item["status"] == "running"
        store._conn.close()

    def test_keyerror_on_missing(self, tmp_path):
        """不存在的 key 应抛出 KeyError"""
        from pipeline.api import _ScanTaskStore, _init_db
        db_path = tmp_path / "test_missing.db"
        store = _ScanTaskStore.__new__(_ScanTaskStore)
        store._conn = _init_db(db_path)
        with pytest.raises(KeyError):
            _ = store["nonexistent"]
        store._conn.close()

    def test_values_returns_list(self, tmp_path):
        """values() 应返回列表"""
        from pipeline.api import _ScanTaskStore, _init_db
        db_path = tmp_path / "test_values.db"
        store = _ScanTaskStore.__new__(_ScanTaskStore)
        store._conn = _init_db(db_path)
        store["run_a"] = {"status": "pending"}
        store["run_b"] = {"status": "completed"}
        items = store.values()
        assert len(items) == 2
        store._conn.close()

    def test_persistence_across_connections(self, tmp_path):
        """SQLite 持久化：新连接应能读取旧数据"""
        from pipeline.api import _init_db
        db_path = tmp_path / "persist.db"
        conn1 = _init_db(db_path)
        conn1.execute(
            "INSERT INTO scan_tasks (run_id, status, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("persist_run", "pending", "2025-01-01T00:00:00", "2025-01-01T00:00:00"),
        )
        conn1.commit()
        conn1.close()

        # 新连接
        conn2 = _init_db(db_path)
        cur = conn2.execute("SELECT status FROM scan_tasks WHERE run_id=?", ("persist_run",))
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "pending"
        conn2.close()


class TestAPIEndpoints:
    """FastAPI 端点测试（需要 fastapi 安装）"""

    @pytest.fixture
    def api_client(self):
        """创建 TestClient（需要 fastapi + httpx）"""
        try:
            from fastapi.testclient import TestClient
            from pipeline.api import app
            if app is None:
                pytest.skip("FastAPI 不可用")
            return TestClient(app)
        except ImportError:
            pytest.skip("fastapi/httpx 不可用，跳过 API 端点测试")

    def test_health_check(self, api_client):
        """GET /api/v1/health 应返回 healthy"""
        resp = api_client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_start_scan(self, api_client):
        """POST /api/v1/scan 应返回 run_id"""
        resp = api_client.post("/api/v1/scan", json={
            "endpoint": "http://test.example.com/v1",
            "model": "test-model",
            "api_key": "test-key",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert data["status"] == "accepted"

    def test_scan_status_not_found(self, api_client):
        """GET /api/v1/scan/{nonexistent} 应返回 404"""
        resp = api_client.get("/api/v1/scan/nonexistent_run_id")
        assert resp.status_code == 404

    def test_report_not_found(self, api_client):
        """GET /api/v1/report/{nonexistent} 应返回 404"""
        resp = api_client.get("/api/v1/report/nonexistent_run_id")
        assert resp.status_code == 404
