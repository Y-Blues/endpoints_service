"""
ServiceEndpoint: finds a named service and dispatches to it, applying its authorization.

A service overriding IExposedService.call() handles every request itself. Otherwise the request goes to
the service's @rpc_method whose HTTP method and path template ("/{item_id}/execute") match: its
arguments are the path parameters plus the JSON object body, and it receives the request subject as
its `subject` parameter when it declares one.
"""

import dataclasses
import inspect
import logging
import re
from typing import Any, Callable

from ycappuccino.api.decorators import get_rpc_methods
from ycappuccino.api.endpoints_service import CALL, IExposedService, IServiceEndpoint, ServiceResult
from ycappuccino.api.endpoints_storage import Forbidden, IAuthorization, InvalidRequest, NotAuthenticated, NotFound

_logger = logging.getLogger(__name__)

_PATH_PARAM = re.compile(r"\{(\w+)\}")


class ServiceEndpoint(IServiceEndpoint):

    def __init__(self, services: list[IExposedService], authorizations: list[IAuthorization]) -> None:
        self._services = services
        self._authorizations = authorizations

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def call(
        self, name: str, method: str, extra_path: list, params: dict, body: Any, subject: dict | None
    ) -> ServiceResult:
        service = self._find(name)
        await self._check(service, subject)
        return await call_service(service, method, extra_path, params, body, subject)

    def _find(self, name: str) -> IExposedService:
        for service in list(self._services):
            if service.name == name:
                return service
        raise NotFound(f"unknown service {name}")

    async def _check(self, service: IExposedService, subject: dict | None) -> None:
        if not service.secure:
            return
        if subject is None:
            raise NotAuthenticated(f"call {service.name} requires a subject")
        authorizations = list(self._authorizations)
        if not authorizations:
            _logger.warning("no IAuthorization service: call on %s is refused", service.name)
            raise Forbidden(f"call {service.name} is not authorized")
        if not await authorizations[0].is_authorized(subject, CALL, service.name):
            raise Forbidden(f"call {service.name} is not authorized")


async def call_service(
    service: IExposedService, method: str, extra_path: list, params: dict, body: Any, subject: dict | None
) -> ServiceResult:
    """runs a request on a service already found and authorized: its call() if it overrides it, otherwise
    the matching @rpc_method"""
    if handles_its_calls(service):
        return await service.call(method, extra_path, params, body, subject)
    target, path_params = _match(service, method, extra_path)
    result = await target(**_arguments(target, path_params, body, subject))
    return result if isinstance(result, ServiceResult) else ServiceResult(body=_jsonable(result))


def handles_its_calls(service: IExposedService) -> bool:
    """True when the service overrides call() instead of answering through @rpc_method methods"""
    return type(service).call is not IExposedService.call


def _match(service: IExposedService, method: str, extra_path: list) -> tuple[Callable, dict]:
    request_path = "/" + "/".join(extra_path) if extra_path else ""
    for attribute_name, metadata in get_rpc_methods(type(service)).items():
        if metadata["method"] != method:
            continue
        path_params = _match_path(metadata["path"], request_path)
        if path_params is not None:
            return getattr(service, attribute_name), path_params
    raise NotFound(f"no route {method} {request_path!r} on service {service.name}")


def _match_path(template: str, path: str) -> dict | None:
    # the template split on its "{name}" segments alternates literal text and parameter names
    parts = _PATH_PARAM.split(template)
    pattern = "".join(re.escape(part) if index % 2 == 0 else f"(?P<{part}>[^/]+)" for index, part in enumerate(parts))
    match = re.fullmatch(pattern, path)
    return None if match is None else match.groupdict()


def _arguments(target: Callable, path_params: dict, body: Any, subject: dict | None) -> dict:
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise InvalidRequest("the body must be a JSON object of arguments")
    kwargs = {**body, **path_params}
    kwargs.pop("subject", None)
    signature = inspect.signature(target)
    if "subject" in signature.parameters:
        kwargs["subject"] = subject
    try:
        signature.bind(**kwargs)
    except TypeError as error:
        raise InvalidRequest(str(error)) from None
    return kwargs


def _jsonable(result: Any) -> Any:
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        return dataclasses.asdict(result)
    return result
