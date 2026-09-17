import unittest

from service_fixtures import ALICE, FakeAuthorization, FakeExposedService, TypedFakeService

from ycappuccino.api.endpoints_service import CALL
from ycappuccino.api.endpoints_storage import Forbidden, InvalidRequest, NotAuthenticated, NotFound
from ycappuccino.endpoints_service.endpoint import ServiceEndpoint, call_service


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


class TestServiceEndpointTypedDispatch(unittest.IsolatedAsyncioTestCase):

    async def test_routes_to_the_matching_rpc_method(self):
        endpoint = ServiceEndpoint([TypedFakeService()], [])

        result = await endpoint.call("typed", "POST", ["abc", "execute"], {}, {"count": 3}, None)

        self.assertEqual(result.body, {"item_id": "abc", "count": 3})

    async def test_optional_parameters_keep_their_default(self):
        endpoint = ServiceEndpoint([TypedFakeService()], [])

        result = await endpoint.call("typed", "POST", ["abc", "execute"], {}, None, None)

        self.assertEqual(result.body, {"item_id": "abc", "count": 1})

    async def test_unmatched_method_or_path_is_not_found(self):
        endpoint = ServiceEndpoint([TypedFakeService()], [])

        for method, extra_path in (("GET", ["abc", "execute"]), ("POST", ["abc"]), ("POST", ["a", "b", "execute"])):
            with self.subTest(method=method, extra_path=extra_path):
                with self.assertRaises(NotFound):
                    await endpoint.call("typed", method, extra_path, {}, {}, None)

    async def test_a_result_that_is_already_a_service_result_is_used_as_is(self):
        endpoint = ServiceEndpoint([TypedFakeService()], [])

        result = await endpoint.call("typed", "POST", ["cookie"], {}, {}, None)

        self.assertEqual((result.body, result.headers), ({"ok": True}, {"set-cookie": "a=b"}))

    async def test_the_request_subject_is_passed_and_a_body_subject_ignored(self):
        typed = TypedFakeService()
        endpoint = ServiceEndpoint([typed], [])

        result = await endpoint.call("typed", "GET", [], {}, {"subject": {"sub": "mallory"}}, ALICE)

        self.assertEqual(result.body, {"subject": ALICE})

    async def test_unexpected_or_missing_arguments_are_invalid(self):
        endpoint = ServiceEndpoint([TypedFakeService()], [])

        for body in ({"count": 1, "unknown": 2}, ["not", "an", "object"]):
            with self.subTest(body=body):
                with self.assertRaises(InvalidRequest):
                    await endpoint.call("typed", "POST", ["abc", "execute"], {}, body, None)

    async def test_a_service_overriding_call_keeps_it_as_its_handler(self):
        echo = FakeExposedService("echo", secure=False)
        endpoint = ServiceEndpoint([echo], [])

        await endpoint.call("echo", "DELETE", ["any", "path"], {}, None, None)

        self.assertEqual(echo.calls, [("DELETE", ["any", "path"], {}, None, None)])



class TestCallService(unittest.IsolatedAsyncioTestCase):
    """the routing alone, without lookup nor authorization, for another IServiceEndpoint (remote)"""

    async def test_routes_without_checking_the_secure_flag(self):
        typed = TypedFakeService()
        typed.secure = True

        result = await call_service(typed, "POST", ["abc", "execute"], {}, {"count": 2}, None)

        self.assertEqual(result.body, {"item_id": "abc", "count": 2})

    async def test_a_service_overriding_call_gets_the_request(self):
        echo = FakeExposedService("echo", secure=False)

        await call_service(echo, "PUT", ["x"], {"q": "1"}, {"a": 1}, ALICE)

        self.assertEqual(echo.calls, [("PUT", ["x"], {"q": "1"}, {"a": 1}, ALICE)])


if __name__ == "__main__":
    unittest.main()
