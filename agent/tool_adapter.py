"""Send secure tool calls to the Gateway without accessing local files."""

import math
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from secure_agent.common.schemas import ReadFileToolCall, ToolCall, ToolResult, parse_tool_call
from secure_agent.provenance.models import ExposureReceipt


class GatewayError(RuntimeError):
    """A Gateway request failed or returned an invalid response."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class SecureToolAdapter:
    """POST the shared ToolCall contract; expect a matching ToolResult.

    HTTP errors, including the current Gateway's 501, are failures.
    Requests are not retried: a timed-out edit may already have executed.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000", *, timeout: float = 5.0,
                 acknowledge_exposure: bool = False):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite.")
        self.url = base_url.rstrip("/") + "/tools/execute"
        self.timeout = timeout
        self.exposure_url = base_url.rstrip("/") + "/tools/exposure"
        self.acknowledge_exposure = acknowledge_exposure

    def execute(self, call: ToolCall) -> ToolResult:
        call = parse_tool_call(call)
        request = Request(
            self.url,
            data=call.model_dump_json().encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except HTTPError as error:
            error.close()
            raise GatewayError(
                f"Gateway returned HTTP {error.code}.", status_code=error.code
            ) from error
        except TimeoutError as error:
            raise GatewayError("Gateway request timed out.") from error
        except URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise GatewayError("Gateway request timed out.") from error
            raise GatewayError("Gateway connection failed.") from error
        except OSError as error:
            raise GatewayError("Gateway connection failed.") from error

        try:
            result = ToolResult.model_validate_json(body)
        except ValidationError as error:
            raise GatewayError("Gateway returned an invalid ToolResult.") from error
        if result.request_id != call.request_id:
            raise GatewayError("Gateway response request_id does not match.")
        if (self.acknowledge_exposure and isinstance(call, ReadFileToolCall)
                and result.status == "success"):
            receipt = ExposureReceipt(request_id=call.request_id, task_id=call.task_id,
                                      source_id=result.source_id)
            acknowledgement = Request(self.exposure_url, data=receipt.model_dump_json().encode("utf-8"),
                                      headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urlopen(acknowledgement, timeout=self.timeout) as response:
                    if response.status != 204:
                        raise GatewayError("Exposure acknowledgement failed.")
            except HTTPError as error:
                error.close()
                raise GatewayError("Exposure acknowledgement failed.") from error
            except (OSError, TimeoutError) as error:
                raise GatewayError("Exposure acknowledgement failed.") from error
        return result
