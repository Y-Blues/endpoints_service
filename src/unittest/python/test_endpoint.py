import unittest

from service_fixtures import ALICE, FakeAuthorization, FakeExposedService

from ycappuccino.api.endpoints_service import CALL
from ycappuccino.api.endpoints_storage import Forbidden, NotAuthenticated, NotFound
from ycappuccino.endpoints_service.endpoint import ServiceEndpoint


class TestServiceEndpoint(unittest.IsolatedAsyncioTestCase):

    async def test_unknown_service_is_not_found(self):
        endpoint = ServiceEndpoint([], [])

        with self.assertRaises(NotFound):
            await endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None)

    async def test_unsecured_service_is_called_without_a_subject(self):
        echo = FakeExposedService("echo", secure=False)
        endpoint = ServiceEndpoint([echo], [])

        result = await endpoint.call("echo", "POST", ["extra"], {"q": "1"}, {"msg": "hi"}, None)

        self.assertEqual(result.body, {"ok": True})
        self.assertEqual(echo.calls, [("POST", ["extra"], {"q": "1"}, {"msg": "hi"}, None)])

    async def test_secured_service_requires_a_subject(self):
        secret = FakeExposedService("secret")
        endpoint = ServiceEndpoint([secret], [FakeAuthorization()])

        with self.assertRaises(NotAuthenticated):
            await endpoint.call("secret", "POST", [], {}, {}, None)
        self.assertEqual(secret.calls, [])

    async def test_secured_service_without_authorization_is_forbidden(self):
        secret = FakeExposedService("secret")
        endpoint = ServiceEndpoint([secret], [])

        with self.assertLogs("ycappuccino.endpoints_service.endpoint", "WARNING"):
            with self.assertRaises(Forbidden):
                await endpoint.call("secret", "POST", [], {}, {}, ALICE)

    async def test_secured_service_asks_the_authorization(self):
        secret = FakeExposedService("secret")
        authorization = FakeAuthorization(allowed=())
        endpoint = ServiceEndpoint([secret], [authorization])

        with self.assertRaises(Forbidden):
            await endpoint.call("secret", "POST", [], {}, {}, ALICE)

        authorization.allowed = {(CALL, "secret")}
        await endpoint.call("secret", "POST", [], {}, {}, ALICE)

        self.assertEqual(authorization.calls, [("alice", CALL, "secret"), ("alice", CALL, "secret")])
        self.assertEqual(len(secret.calls), 1)

    async def test_authorization_registered_after_construction_is_used(self):
        secret = FakeExposedService("secret")
        authorizations = []
        endpoint = ServiceEndpoint([secret], authorizations)
        authorizations.append(FakeAuthorization())

        await endpoint.call("secret", "POST", [], {}, {}, ALICE)

        self.assertEqual(len(secret.calls), 1)


if __name__ == "__main__":
    unittest.main()
