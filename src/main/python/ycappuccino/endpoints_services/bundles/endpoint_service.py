"""
    handler endpoint that manage call of service
"""

from ycappuccino.api.core.api import IActivityLogger
from ycappuccino.api.proxy.api import YCappuccinoRemote
from ycappuccino.core.decorator_app import Layer

import logging
from ycappuccino.endpoints.beans import UrlPath, EndpointResponse
from pelix.ipopo.decorators import (
    ComponentFactory,
    Requires,
    Validate,
    Invalidate,
    Provides,
    BindField,
    UnbindField,
    Instantiate,
)

from ycappuccino.api.core.api import IService
from ycappuccino.api.endpoints.api import IEndpoint

_logger = logging.getLogger(__name__)

from ycappuccino.endpoints.bundles.utils_header import (
    check_header,
    get_token_from_header,
)
from ycappuccino.api.endpoints.api import IRightManager, IHandlerEndpoint


@ComponentFactory("EndpointService-Factory")
@Provides(specifications=[YCappuccinoRemote.__name__, IHandlerEndpoint.__name__])
@Requires("_log", IActivityLogger.__name__, spec_filter="'(name=main)'")
@Instantiate("handlerEndpointService")
@Requires(
    "_handler_swagger",
    specification=IHandlerEndpoint.__name__,
    spec_filter="'(name=swagger)'",
)
@Requires("_services", specification=IService.__name__, aggregate=True, optional=True)
@Requires("_endpoint", specification=IEndpoint.__name__)
@Requires("_right_access", specification=IRightManager.__name__, optional=True)
@Layer(name="ycappuccino_endpoints_service")
class HandlerEndpointService(IHandlerEndpoint):

    def __init__(self):
        super(IHandlerEndpoint, self).__init__()
        self._log = None
        self._endpoint = None
        self._services = None
        self._map_services = {}
        self._file_dir = None
        self._right_access = None
        self._handler_swagger = None

    def find_service(self, a_item_id):
        if a_item_id in self._map_services:
            return self._map_services[a_item_id]
        return None

    def get_types(self):
        return ["service"]

    def post(self, a_path, a_headers, a_body):
        w_url_path = UrlPath(
            "post", a_path, self._handler_swagger.get(a_path, a_headers)
        )
        w_service_name = w_url_path.get_service_name()
        w_service = self.find_service(w_service_name)
        if w_service.is_secure():
            if self._right_access is None:
                self._log.info("service authorization service not available")
                return EndpointResponse(500)
            if not check_header(self._right_access, a_headers):
                self._log.info("failed authorization service ")
                return EndpointResponse(401)
            w_token = get_token_from_header(a_headers)
            if not self._right_access.is_authorized(w_token, w_url_path):
                self._log.info("failed authorization service ")
                return EndpointResponse(403)

            w_header, w_body = w_service.post(a_headers, w_url_path, a_body)
            w_meta = {"type": "array"}

            return EndpointResponse(200, w_header, w_meta, w_body)
        else:
            w_header, w_body = w_service.post(a_headers, w_url_path, a_body)
            w_meta = {"type": "array"}
            if w_body is None:
                return EndpointResponse(401)
            else:
                return EndpointResponse(200, w_header, w_meta, w_body)

    def put(self, a_path, a_headers, a_body):
        w_url_path = UrlPath(
            "put", a_path, self._handler_swagger.get(a_path, a_headers)
        )
        w_service_name = w_url_path.get_service_name()
        w_service = self.find_services(w_service_name)
        if w_service is not None:
            if w_service.is_secure():
                if self._right_access is None:
                    self._log.info("service authorization service not available")
                    return EndpointResponse(500)

                if not check_header(self._right_access, a_headers):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(401)
                w_token = get_token_from_header(a_headers)
                if not self._right_access.is_authorized(w_token, w_url_path):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(403)

                w_header, w_body = w_service.put(a_headers, w_url_path, a_body)
                w_meta = {"type": "array"}
                return EndpointResponse(200, w_header, w_meta, w_body)

            else:
                w_header, w_body = w_service.put(a_headers, w_url_path, a_body)
                w_meta = {"type": "array"}
                return EndpointResponse(200, w_header, w_meta, w_body)
        return EndpointResponse(501)

    def get_swagger_descriptions(self, a_tag, a_swagger, a_scheme):

        self._handler_swagger.get_swagger_description_item(a_swagger["paths"])
        for w_item in ycappuccino_core.models.decorators.get_map_items():
            if not w_item["abstract"]:
                self._handler_swagger.get_swagger_description(
                    w_item, a_swagger["paths"]
                )
                a_tag.append(
                    {"name": self._handler_swagger.get_swagger_description_tag(w_item)}
                )

        for w_service in self._map_services.values():
            self._handler_swagger.get_swagger_description_service(
                w_service, a_swagger["paths"]
            )
            a_tag.append(
                {
                    "name": self._handler_swagger.get_swagger_description_service_tag(
                        w_service
                    )
                }
            )

        return EndpointResponse(200, None, None, a_swagger)

    def get(self, a_path, a_headers):
        w_url_path = UrlPath(
            "get", a_path, self._handler_swagger.get(a_path, a_headers)
        )
        w_service_name = w_url_path.get_service_name()
        w_service = self.find_services(w_service_name)
        if w_service is not None:
            if w_service.is_secure():
                if self._right_access is not None:
                    self._log.info("service authorization service not available")
                    return EndpointResponse(500)
                if not check_header(self._right_access, a_headers):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(401)
                w_token = get_token_from_header(a_headers)
                if not self._right_access.is_authorized(w_token, w_url_path):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(403)

                w_header, w_body = w_service.get(a_headers, w_url_path)
                w_meta = {"type": "array"}
                if w_body is None:
                    return EndpointResponse(401)
                else:
                    return EndpointResponse(200, w_header, w_meta, w_body)
            else:
                w_header, w_body = w_service.get(a_headers, w_url_path)
                w_meta = {"type": "array"}
                return EndpointResponse(200, w_header, w_meta, w_body)
        return EndpointResponse(501)

    def delete(self, a_path, a_headers):
        w_url_path = UrlPath(
            "delete", a_path, self._handler_swagger.get(a_path, a_headers)
        )
        w_service_name = w_url_path.get_service_name()
        w_service = self.find_services(w_service_name)
        if w_service is not None:
            if w_service.is_secure():
                if self._right_access is not None:
                    self._log.info("service authorization service not available")
                    return EndpointResponse(500)
                if not check_header(self._right_access, a_headers):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(401)
                w_token = get_token_from_header(a_headers)
                if not self._right_access.is_authorized(w_token, w_url_path):
                    self._log.info("failed authorization service ")
                    return EndpointResponse(403)
            else:
                w_header, w_body = w_service.delete(a_headers, w_url_path)
                w_meta = {"type": "array"}
                return EndpointResponse(200, w_header, w_meta, w_body)

    @BindField("_services")
    def bind_services(self, field, a_service, a_service_reference):
        w_service = a_service.get_name()
        self._map_services[w_service] = a_service

    @UnbindField("_services")
    def unbind_services(self, field, a_service, a_service_reference):
        w_service = a_service.get_name()
        self._map_services[w_service] = None

    @Validate
    def validate(self, context):
        self._log.info("HandlerEndpointService validating")

        self._log.info("HandlerEndpointStorage validated")

    @Invalidate
    def invalidate(self, context):
        self._log.info("HandlerEndpointService invalidating")

        self._log.info("HandlerEndpointStorage invalidated")
