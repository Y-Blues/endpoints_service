"""
Fakes shared by the endpoints_service tests.
"""

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
