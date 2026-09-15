"""
The examples of README.md, kept runnable.
"""

import unittest

from ycappuccino.api.endpoints_service import IExposedService, IServiceEndpoint, ServiceResult
from ycappuccino.api.core_base import YCappuccinoComponent
from ycappuccino.endpoints_service.endpoint import ServiceEndpoint


# section "Déclarer un service"
class Echo(IExposedService):
    name = "echo"
    secure = False

    def __init__(self):
        pass

    async def call(self, method, extra_path, params, body, subject):
        return ServiceResult(body={"echo": body})

    async def start(self):
        pass

    async def stop(self):
        pass


# section "Appeler un service"
class Caller(YCappuccinoComponent):
    def __init__(self, endpoint: IServiceEndpoint):
        self._endpoint = endpoint

    async def start(self):
        self.result = await self._endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None)

    async def stop(self):
        pass


class TestReadmeExamples(unittest.IsolatedAsyncioTestCase):

    async def test_calling_section(self):
        endpoint = ServiceEndpoint([Echo()], [])
        caller = Caller(endpoint)

        await caller.start()

        self.assertEqual(caller.result.body, {"echo": {"msg": "hi"}})

    async def test_testing_section(self):
        endpoint = ServiceEndpoint([Echo()], [])
        result = await endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None)

        self.assertEqual(result.body, {"echo": {"msg": "hi"}})


if __name__ == "__main__":
    unittest.main()
