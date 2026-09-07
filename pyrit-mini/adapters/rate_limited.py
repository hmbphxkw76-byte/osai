"""RateLimitedTarget - PyRIT 

 (Production-grade PyRIT 1.0.1 ):
    PyRIT 1.0.1's OpenAIChatTarget / OpenAIResponseTarget / HTTPTarget
     + Retry:

    1. ''@limit_requests_per_minute'' - PyRIT  RPM rate limit
        ''_send_prompt_to_target_async''  ''asyncio.sleep(60/rpm)''
       : ''pyrit.prompt_target.common.utils''

    2. ''@pyrit_target_retry'' - PyRIT Retry (tenacity )
 Retry ''RateLimitError''''EmptyResponseException''
       ''RateLimitException'' + 
       : ''pyrit.exceptions.exception_classes''
       :  ''RETRY_MAX_NUM_ATTEMPTS'' ( 10)
       ''RETRY_WAIT_MIN_SECONDS'' ( 5)''RETRY_WAIT_MAX_SECONDS'' ( 220)

    3. ''_handle_openai_request_async'' - OpenAITarget Error handling
 ''BadRequestError''''RateLimitError''
 ''APIStatusError''''APITimeoutError''''APIConnectionError''
       ''AuthenticationError''
        ''Retry-After''  ''x-request-id''

    RateLimitedTarget :
        - **** (''asyncio.Semaphore''): 
          PyRIT  ()
        - **** (401/403):  token  / 
          Academic basis: Heroux et al. (arXiv:2403.04206) Sec3.2
        - **Capability verification**:  PyRIT  ''TargetRequirements.validate()''
           text 
        - ****: ''dispose_db_engine()'' + httpx client 

     (vs Retry):
        -  ''_classify_error'' + ''_send_with_retry'' 
        -  HTTP 
        -  (PyRIT )
        -  (PyRIT )
        -  ''@limit_requests_per_minute''  ''@pyrit_target_retry''
          (Not overridden target  ''_send_prompt_to_target_async'')

Academic basis:
    - PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
    - Greshake et al. (arXiv:2302.12173) - 
    - Heroux et al. (arXiv:2403.04206) - 
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pyrit.prompt_target.common.prompt_target import PromptTarget

logger = logging.getLogger(__name__)

# - token / 
_AUTH_RECOVERABLE_STATUS_CODES = frozenset({401, 403})


class RateLimitedTarget(PromptTarget):
 """PyRIT PromptTarget 

    Aligned with PyRIT 1.0.1 architecture:
         ''PromptTarget'' ''@final send_prompt_async'' 
         ''RateLimitedTarget'' :
        - ''send_prompt_async''  validation + normalization + conversation
           ''RateLimitedTarget'' 
        - ''self._send_prompt_to_target_async'' 
          ''RateLimitedTarget._send_prompt_to_target_async'' ( +
          )

     (PyRIT ):
        - **Not overridden**  target  ''_send_prompt_to_target_async''
           ''self._target._send_prompt_to_target_async()''
           target :
          ''@limit_requests_per_minute'' + ''@pyrit_target_retry''
        -  (Semaphore) 

     (PyRIT ):
        - : ''asyncio.Semaphore(max_concurrency)'' 
        - : 401/403  token  / 
        - Capability verification: ''TargetRequirements.validate()'' 
        - : ''dispose_db_engine()'' + httpx client 

    Args:
        target:  PromptTarget 
        endpoint:  URL (, None imports target )
        max_concurrency:  (PyRIT )
        auth_state_manager:  ()
        auth_state:  ()
 """

    def __init__(
        self,
        *,
        target: PromptTarget,
        endpoint: str | None = None,
        max_concurrency: int = 3,
        auth_state_manager: Any | None = None,
        auth_state: Any | None = None,
    ) -> None:
        self._target = target
        self._endpoint = endpoint or getattr(target, "_endpoint", str(id(target)))
        self._semaphore = asyncio.Semaphore(max_concurrency)

 # ()
        self._auth_manager = auth_state_manager
        self._auth_state = auth_state
 # TLS ( auth_manager URL)
        self._use_tls = getattr(target, "_use_tls", True)

 # PyRIT 1.0.1: super().__init__ PromptTarget 
 # send_prompt_async (final) RateLimitedTarget ,
 # self._send_prompt_to_target_async RateLimitedTarget 
 # custom_configuration target , ADAPT/RAISE 
 # max_requests_per_minute target RPM ()
        effective_rpm = getattr(target, "_max_requests_per_minute", None)

        super().__init__(
            max_requests_per_minute=effective_rpm,
            endpoint=self._endpoint,
            model_name=getattr(target, "_model_name", ""),
            underlying_model=getattr(target, "_underlying_model", None),
            custom_configuration=getattr(target, "_configuration", None),
        )

 # 
        self._endpoint_attr = getattr(target, "_endpoint", "")
        self._identifier = getattr(target, "_identifier", None)
        self.supported_converters = getattr(target, "supported_converters", [])

 # Capability verification - PyRIT TargetRequirements.validate()
        self._validate_target_capabilities(target)

 # capabilities , discover_target_capabilities 
        self._target_capabilities = getattr(target, "capabilities", None)

    def _validate_target_capabilities(self, target: PromptTarget) -> None:
 """

         PyRIT  ''TargetRequirements.validate()'' 
         text  ()

        Academic basis:
            - PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
            - Greshake et al. (arXiv:2302.12173) - 
 """
        try:
            from pyrit.prompt_target.common.target_requirements import TargetRequirements

 # : text /
            requirements = TargetRequirements(
                required=frozenset(),
                native_required=frozenset(),
                required_input_modalities=frozenset({frozenset({"text"})}),
                required_output_modalities=frozenset({frozenset({"text"})}),
            )
            requirements.validate(target=target)
        except ValueError as e:
            logger.warning(
                "Target %s failed TargetRequirements validation: %s; "
                "text-based attacks may fail",
                type(target).__name__,
                e,
            )
        except Exception as e:
 # configuration ( HTTPTarget )
            logger.debug(
                "Capability validation skipped for %s (non-fatal): %s",
                type(target).__name__,
                e,
            )

    async def apply_discovered_capabilities(self, *, timeout_s: float = 30.0) -> None:
 """ PyRIT ''discover_target_capabilities'' 

        PyRIT :
            -  multi_turn, system_prompt, json_output 
            -  input_modalities (text, image_path, audio_path)
            -  (apply=True)
            - , 

        Academic basis:
            - PyRIT (arXiv:2407.01232) - Capability discovery
            - Greshake et al. (arXiv:2302.12173) - 

        Args:
            timeout_s: converter(s) ()
 """
        try:
            from pyrit.prompt_target.common.discover_target_capabilities import (
                discover_target_capabilities_async,
            )

            logger.info(
                "Running PyRIT native capability discovery on %s",
                type(self._target).__name__,
            )
            discovered = await discover_target_capabilities_async(
                target=self._target,
                per_probe_timeout_s=timeout_s,
                apply=True,
            )
            self._target_capabilities = discovered
            logger.info(
                "Discovered capabilities: multi_turn=%s, "
                "system_prompt=%s, json_output=%s, "
                "input_modalities=%s",
                discovered.supports_multi_turn,
                discovered.supports_system_prompt,
                discovered.supports_json_output,
                [sorted(s) for s in sorted(discovered.input_modalities)],
            )
        except Exception as e:
            logger.warning(
                "Native capability discovery failed (non-fatal): %s", e
            )

    async def _send_prompt_to_target_async(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
 """ + prompt 

        PyRIT :
             ''self._target._send_prompt_to_target_async()''
             target :
            - ''@limit_requests_per_minute'' - PyRIT  RPM rate limit
            - ''@pyrit_target_retry'' - PyRIT Retry (tenacity)
               RateLimitErrorEmptyResponseException
              RateLimitException Retry

         (PyRIT ):
            1.  ()
            2.  target._send_prompt_to_target_async()
               ( @limit_requests_per_minute + @pyrit_target_retry)
            3.  (401/403) -  token /
            4.  ->  headers Retry
            5.  -> raise
 """
        async with self._semaphore:
            return await self._send_with_auth_recovery(
                normalized_conversation=normalized_conversation,
            )

    async def _send_with_auth_recovery(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
 """

        PyRIT  ''@pyrit_target_retry'' :
        - RateLimitError (429) - Retry
        - EmptyResponseException (204) - Retry
        - RateLimitException - Retry
        - APITimeoutError / APIConnectionError - Retry

         PyRIT Not overridden (401/403)
        Academic basis: Heroux et al. (arXiv:2403.04206) Sec3.2 - 
 """
        try:
 # target _send_prompt_to_target_async
 # : @limit_requests_per_minute + @pyrit_target_retry
            return await self._target._send_prompt_to_target_async(
                normalized_conversation=normalized_conversation,
            )
        except Exception as e:
 # (401/403)
            if not self._is_auth_recoverable(e):
                raise

 # 
            if not self._auth_manager or not self._auth_state:
                raise

            logger.warning("Auth error (401/403), attempting recovery...")
            host = getattr(self, "_endpoint_attr", "")
            if ":" in str(host):
                host = str(host).split(":")[0]
            use_tls = getattr(self, "_use_tls", True)

            recovered = await self._auth_manager.try_recover_auth(
                self._auth_state,
                host=host,
                use_tls=use_tls,
            )

            if not recovered:
                logger.warning("Auth recovery failed, raising error")
                raise

 # - headers Retry
            new_headers = self._auth_manager.build_auth_headers(self._auth_state)
            if hasattr(self._target, "_raw_headers"):
                self._target._raw_headers = new_headers
            if hasattr(self._target, "_headers"):
                self._target._headers = dict(new_headers)
            logger.info("Auth recovered, retrying with new credentials")

 # Retry ( RateLimit/Timeout Retry)
            return await self._target._send_prompt_to_target_async(
                normalized_conversation=normalized_conversation,
            )

    @staticmethod
    def _is_auth_recoverable(exc: Exception) -> bool:
 """ (401/403)

        PyRIT  OpenAITarget  ''AuthenticationError'' 
         401/403 

        Args:
            exc: 

        Returns:
            True 
 """
        exc_name = type(exc).__name__
 # OpenAI SDK AuthenticationError
        if exc_name == "AuthenticationError":
            return True
 # 
        exc_str = str(exc).lower()
        return any(str(code) in exc_str for code in _AUTH_RECOVERABLE_STATUS_CODES)

    async def cleanup(self) -> None:
 """ - Production-grade (, )

        , Ensure:
            1.  target  httpx.AsyncClient 
            2.  target  cleanup 
            3. PyRIT  ''dispose_db_engine()'' 

        :  ''_is_cleaned'' , 
         ''main.py._cleanup_resources''  finally  -
         cleanup, finally 
 """
        if getattr(self, "_is_cleaned", False):
            logger.debug("Cleanup already done for endpoint=%s, skipping", self._endpoint)
            return
        self._is_cleaned = True

 # 1. target httpx client ()
        target = self._target
        if hasattr(target, "_client") and target._client is not None:
            try:
                await target._client.aclose()
                logger.debug("Closed httpx.AsyncClient for %s", type(target).__name__)
            except Exception as e:
                logger.debug("Error closing httpx client (non-fatal): %s", e)

 # 2. target cleanup , 
        if hasattr(target, "cleanup") and callable(getattr(target, "cleanup", None)):
            try:
                result = target.cleanup()
 # , await 
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.debug("Target cleanup failed (non-fatal): %s", e)

 # 3. PyRIT 1.0.1: dispose_db_engine 
        try:
            self.dispose_db_engine()
            logger.debug("Disposed DB engine for %s", type(target).__name__)
        except Exception as e:
            logger.debug("dispose_db_engine failed (non-fatal): %s", e)

        logger.debug("RateLimitedTarget cleanup complete for endpoint=%s", self._endpoint)

    def __getattr__(self, name: str) -> Any:
 """ Target

        :  RateLimitedTarget 
         __init__ 
 """
        return getattr(self._target, name)
