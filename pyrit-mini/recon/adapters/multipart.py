"""recon/adapters/multipart.py — multipart/form-data 协议适配器（REQ-149 ②）。

文件上传是 LLM 应用的高价值攻击面（文档注入 / 解析器绕过 / 存储型注入）。
本适配器把 payload 作为**文件部件**投递，字段与文件名可配置，认证/会话态自动闭合。
"""

from __future__ import annotations

import logging
from typing import Any

from recon.adapters.base import AdapterRequest, AdapterResponse, AuthState, BaseAdapter, SessionState

logger = logging.getLogger(__name__)

DEFAULT_FILE_FIELD = "file"
DEFAULT_FILE_NAME = "payload.txt"
DEFAULT_CONTENT_TYPE = "text/plain"


class MultipartAdapter(BaseAdapter):
    """`multipart/form-data` adapter：prompt 作为文件部件，附加以 form 字段。"""

    name = "multipart"

    def __init__(
        self,
        *,
        file_field: str = DEFAULT_FILE_FIELD,
        file_name: str = DEFAULT_FILE_NAME,
        file_content_type: str = DEFAULT_CONTENT_TYPE,
        fields: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.file_field = file_field
        self.file_name = file_name
        self.file_content_type = file_content_type
        self.fields = dict(fields or {})

    def build_request(self, prompt: str, *, session: SessionState | None = None) -> AdapterRequest:
        request = super().build_request(prompt, session=session)
        request.body = dict(self.fields)
        request.files = {
            self.file_field: (self.file_name, (prompt or "").encode("utf-8"), self.file_content_type),
        }
        return request

    async def send_request(self, request: AdapterRequest) -> AdapterResponse:
        client = self._http_client()
        headers = request.headers or self.build_headers()
        # multipart 边界由客户端生成，显式 Content-Type 会让服务端解析失败
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        form_data = {
            k: str(v)
            for k, v in (request.body or {}).items()
            if k != "_raw" and v is not None
        }
        files = request.files or {self.file_field: (self.file_name, b"", self.file_content_type)}
        try:
            response = await client.request(request.method, request.url, headers=headers, data=form_data, files=files)
        except Exception as e:
            logger.debug("[Adapter:multipart] upload failed: %s", e)
            return AdapterResponse(status=0, error=f"{type(e).__name__}: {e}")

        return self._normalize(response)

    @classmethod
    def from_target(
        cls,
        *,
        url: str,
        raw_headers: Any = None,
        file_field: str = DEFAULT_FILE_FIELD,
        file_name: str = DEFAULT_FILE_NAME,
        fields: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> "MultipartAdapter":
        return cls(
            url=url,
            method="POST",
            auth=AuthState.from_raw_headers(raw_headers),
            session=SessionState(),
            file_field=file_field,
            file_name=file_name,
            fields=fields,
            **kwargs,
        )
