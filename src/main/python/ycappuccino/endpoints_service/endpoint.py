"""
ServiceEndpoint: finds a named service and dispatches to it, applying its authorization.
"""

import logging
from typing import Any

from ycappuccino.api.endpoints_service import CALL, IExposedService, IServiceEndpoint, ServiceResult
from ycappuccino.api.endpoints_storage import Forbidden, IAuthorization, NotAuthenticated, NotFound

_logger = logging.getLogger(__name__)


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
        return await service.call(method, extra_path, params, body, subject)

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
