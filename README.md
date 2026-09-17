# ycappuccino-endpoints-service

Cas d'usage d'appel de services : un service natif expose une action indépendamment du transport ; `IServiceEndpoint` le trouve par son nom et le sécurise avant de l'appeler.

Conception : [docs/superpowers/specs/2026-09-15-endpoints-service-design.md](docs/superpowers/specs/2026-09-15-endpoints-service-design.md).

Prérequis : lire le [README de core](../core/README.md).

## Mise en place

```bash
uv add --editable ../endpoints_service
```

`conf/application.yml` :

```yaml
bundle_prefix:
  - ycappuccino.endpoints_service
  - myapp
```

Le service `IServiceEndpoint` est publié dès que le package est chargé.

## Déclarer un service

Un service répond par ses méthodes marquées `@rpc_method` (`ycappuccino.api.decorators`) :

```python
from ycappuccino.api.decorators import rpc_method
from ycappuccino.api.endpoints_service import IExposedService


class Greeting(IExposedService):
    name = "greeting"
    secure = False

    def __init__(self):
        pass

    async def start(self):
        pass

    async def stop(self):
        pass

    @rpc_method(method="POST", path="/{language}", summary="greet someone")
    async def greet(self, language: str, who: str) -> dict:
        return {"text": ("Bonjour " if language == "fr" else "Hello ") + who}

    @rpc_method(method="GET", path="/me")
    async def me(self, subject: dict | None) -> str:
        return subject["sub"] if subject else "anonymous"
```

`name` identifie le service ; `secure` (par défaut `True`) exige un sujet et une autorisation.

Une requête est routée vers la méthode dont le verbe HTTP et le gabarit de chemin (après le nom du service,
`"{nom}"` pour un segment variable) correspondent ; aucune → `NotFound`. La méthode reçoit en arguments les
segments variables et les clés du corps (un objet JSON), plus le sujet authentifié si elle déclare un
paramètre `subject` (un `subject` du corps est ignoré). Argument inconnu ou manquant, corps qui n'est pas un
objet → `InvalidRequest`. Un résultat `ServiceResult` est renvoyé tel quel, une dataclass devient son objet
JSON, toute autre valeur devient le corps.

`POST /api/services/greeting/fr` avec `{"who": "Alice"}` répond donc `{"text": "Bonjour Alice"}`.

## Gérer toutes les requêtes soi-même

Un service qui redéfinit `call` traite lui-même toutes ses requêtes, sans routage par méthode (c'est le cas
de `__remote_dispatch__` dans `remote`) :

```python
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
```

`call` reçoit le verbe HTTP, les segments de chemin après le nom du service (`extra_path`, une liste), la query string, le corps décodé et le sujet. Il lève `NotFound` (`ycappuccino.api.endpoints_storage`) pour une combinaison non supportée.

## Autorisation

Un service `secure=True` est contrôlé comme un item d'`endpoints_storage` : sujet absent → `NotAuthenticated` ; aucune `IAuthorization` publiée → `Forbidden` (fermé par défaut) ; sinon `IAuthorization.is_authorized(subject, "call", nom_du_service)` décide.

## En-têtes de réponse

`ServiceResult.headers` transporte des en-têtes supplémentaires (par exemple `Set-Cookie` pour un service de login) ; l'adaptateur HTTP les reporte sur sa réponse.

## Appeler un service

```python
from ycappuccino.api.core_base import YCappuccinoComponent
from ycappuccino.api.endpoints_service import IServiceEndpoint


class Caller(YCappuccinoComponent):
    def __init__(self, endpoint: IServiceEndpoint):
        self._endpoint = endpoint

    async def start(self):
        result = await self._endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None)
        print(result.body)  # {"echo": {"msg": "hi"}}

    async def stop(self):
        pass
```

## Tester avec endpoints_service

```python
import unittest

from ycappuccino.endpoints_service.endpoint import ServiceEndpoint


class TestEcho(unittest.IsolatedAsyncioTestCase):
    async def test_echo(self):
        from ycappuccino.api.endpoints_service import IExposedService, ServiceResult

        class Echo(IExposedService):
            name = "echo"
            secure = False

            async def call(self, method, extra_path, params, body, subject):
                return ServiceResult(body={"echo": body})

            async def start(self):
                pass

            async def stop(self):
                pass

        endpoint = ServiceEndpoint([Echo()], [])
        result = await endpoint.call("echo", "POST", [], {}, {"msg": "hi"}, None)

        self.assertEqual(result.body, {"echo": {"msg": "hi"}})
```

## Développer endpoints_service

```bash
uv sync
uv run python -m unittest discover -s src/unittest/python
```

L'exemple `example/` se lance avec `cd example && uv run --project .. ycappuccino`.
