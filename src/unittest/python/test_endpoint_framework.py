import asyncio
import unittest

from ycappuccino.core.framework import Framework
from ycappuccino.core.testing import TemporaryApplication, wait_until

APPLICATION = {
    "conf/application.yml": """
        name: servicetest
        bundle_prefix:
          - ycappuccino.endpoints_service
          - PACKAGE
        config:
          shell:
            console: false
    """,
    "PACKAGE/__init__.py": "",
    "PACKAGE/echo.py": """
        from ycappuccino.api.endpoints_service import IExposedService, ServiceResult


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
    """,
}


class TestServiceEndpointInFramework(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = TemporaryApplication(APPLICATION).open()
        cls.addClassCleanup(cls.app.close)
        cls.framework = Framework()
        cls.framework.init(cls.app.yml_path)
        cls.addClassCleanup(cls.framework.stop)
        wait_until(lambda: cls.framework.context.get_service_reference("ServiceEndpoint"))

    def test_service_endpoint_dispatches_to_the_registered_service(self):
        reference = self.framework.context.get_service_reference("ServiceEndpoint")
        endpoint = self.framework.context.get_service(reference)

        result = asyncio.run(endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None))

        self.assertEqual(result.body, {"echo": {"msg": "hi"}})


if __name__ == "__main__":
    unittest.main()
