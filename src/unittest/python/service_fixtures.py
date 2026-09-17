"""
Fakes shared by the endpoints_service tests.
"""

from ycappuccino.api.decorators import rpc_method
from ycappuccino.api.endpoints_service import IExposedService, ServiceResult
from ycappuccino.api.endpoints_storage import IAuthorization

ALICE = {"sub": "alice", "tid": "acme"}


class FakeExposedService(IExposedService):

    def __init__(self, name, secure=True):
        self.name = name
        self.secure = secure
        self.calls = []
        self.error = None
        self.result = ServiceResult(body={"ok": True})

    async def call(self, method, extra_path, params, body, subject):
        self.calls.append((method, extra_path, params, body, subject))
        if self.error is not None:
            raise self.error
        return self.result

    async def start(self):
        pass

    async def stop(self):
        pass


class FakeAuthorization(IAuthorization):
    """authorizes the (action, resource) pairs of allowed; "*" authorizes everything"""

    def __init__(self, allowed=("*",)):
        self.allowed = set(allowed)
        self.calls = []

    async def is_authorized(self, subject, action, item_id):
        self.calls.append((subject["sub"], action, item_id))
        return "*" in self.allowed or (action, item_id) in self.allowed

    async def start(self):
        pass

    async def stop(self):
        pass


class TypedFakeService(IExposedService):
    """answers through @rpc_method methods instead of a generic call()"""

    name = "typed"
    secure = False

    def __init__(self):
        self.subjects = []

    async def start(self):
        pass

    async def stop(self):
        pass

    @rpc_method(method="POST", path="/{item_id}/execute", summary="run")
    async def execute(self, item_id: str, count: int = 1) -> dict:
        return {"item_id": item_id, "count": count}

    @rpc_method(method="GET")
    async def whoami(self, subject: dict | None) -> dict:
        self.subjects.append(subject)
        return {"subject": subject}

    @rpc_method(method="POST", path="/cookie")
    async def cookie(self) -> ServiceResult:
        return ServiceResult(body={"ok": True}, headers={"set-cookie": "a=b"})
