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
