# endpoints_service natif : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cas d'usage d'appel de services (`ServiceEndpoint` sur `list[IExposedService]`), sécurisé par `IAuthorization`, et sa route `/api/services/...` dans `http_server`.

**Architecture:** Contrat `api.endpoints_service` (`ServiceResult`, `IExposedService`, `IServiceEndpoint`), réutilisant la famille d'erreurs et le port `IAuthorization` d'`endpoints_storage`. `endpoints_service` implémente `ServiceEndpoint`, composant natif sans décorateur. `http_server` ajoute une famille de route de plus à `ApiServlet`, avec `services: list[IServiceEndpoint]` en liste vivante.

**Tech Stack:** Python ≥ 3.10, uv, Pelix/iPOPO 3, unittest (`IsolatedAsyncioTestCase`), `ycappuccino.api.endpoints_storage` (réutilisé), `ycappuccino.api.http`/`http_server`.

**Spec:** `endpoints_service/docs/superpowers/specs/2026-09-15-endpoints-service-design.md`

## Global Constraints

- Chemins relatifs à la racine du workspace `/home/apisu/Documents/perso/repositories` ; `api`, `endpoints_service`, `http_server` sont des dépôts git séparés.
- Commande de test, lancée depuis le dépôt concerné : `uv run python -m unittest discover -s src/unittest/python`.
- `requires-python = ">=3.10"`.
- **Aucun décorateur sur les classes de composants.**
- `services` (dans `ApiServlet`) est une **liste vivante** (`list[IServiceEndpoint]`), jamais `Optional[IServiceEndpoint]` : `endpoints_service` est un bundle séparé qui peut démarrer après `http_server` selon l'ordre de `bundle_prefix` ; une dépendance optionnelle simple ne serait relue qu'à la validation et resterait `None` si l'ordre est défavorable.
- `IExposedService`/`IServiceEndpoint` réutilisent `NotAuthenticated`, `Forbidden`, `NotFound`, `InvalidRequest` et `IAuthorization` d'`ycappuccino.api.endpoints_storage` — pas de nouvelle hiérarchie d'erreurs.
- Committer après la revue de chaque tâche, jamais pendant qu'un sous-agent travaille encore dans le même dépôt ; messages de commit courts, sans ligne d'attribution.

## Structure des fichiers

| Fichier | Responsabilité |
|---|---|
| `api/src/main/python/ycappuccino/api/endpoints_service.py` (créé) | `CALL`, `ServiceResult`, `IExposedService`, `IServiceEndpoint` |
| `endpoints_service/src/main/python/ycappuccino/endpoints_service/endpoint.py` | `ServiceEndpoint` |
| `http_server/src/main/python/ycappuccino/http_server/servlet.py` (modifié) | route `/services`, `_ok` gagne `headers` |
| `http_server/src/unittest/python/servlet_fixtures.py` (modifié) | `FakeServiceEndpoint`, `create_servlet` gagne `services` |

---

### Task 1: api, contrat `endpoints_service`

**Files:**
- Create: `api/src/main/python/ycappuccino/api/endpoints_service.py`
- Test: `api/src/unittest/python/test_interfaces.py` (ajout d'une classe)

**Interfaces:**
- Produces: `ycappuccino.api.endpoints_service` avec `CALL = "call"` ; `ServiceResult(body, headers={})` (dataclass, `headers` via `field(default_factory=dict)`) ; `IExposedService(YCappuccinoComponent, ABC)` avec `name: str = ""`, `secure: bool = True`, `async def call(self, method, extra_path, params, body, subject) -> ServiceResult` ; `IServiceEndpoint(YCappuccinoComponent, ABC)` avec `async def call(self, name, method, extra_path, params, body, subject) -> ServiceResult`.

- [ ] **Step 1: Write the failing test**

Ajouter à `api/src/unittest/python/test_interfaces.py`, avant `if __name__ == "__main__":` :

```python
class TestEndpointsServiceInterfaces(unittest.TestCase):

    def test_interfaces_are_abstract_components(self):
        from ycappuccino.api.endpoints_service import IExposedService, IServiceEndpoint

        for klass in (IExposedService, IServiceEndpoint):
            with self.subTest(interface=klass.__name__):
                self.assertTrue(issubclass(klass, YCappuccinoComponent))
                self.assertTrue(inspect.isabstract(klass))

    def test_call_is_a_coroutine(self):
        from ycappuccino.api.endpoints_service import IExposedService, IServiceEndpoint

        self.assertTrue(inspect.iscoroutinefunction(IExposedService.call))
        self.assertTrue(inspect.iscoroutinefunction(IServiceEndpoint.call))

    def test_exposed_service_defaults(self):
        from ycappuccino.api.endpoints_service import IExposedService

        self.assertEqual((IExposedService.name, IExposedService.secure), ("", True))

    def test_service_result_is_a_dataclass_with_independent_headers(self):
        from ycappuccino.api.endpoints_service import ServiceResult

        result = ServiceResult(body={"a": 1})
        result.headers["x"] = "1"

        self.assertEqual(result.body, {"a": 1})
        self.assertEqual(ServiceResult(body=None).headers, {})

    def test_call_action(self):
        from ycappuccino.api.endpoints_service import CALL

        self.assertEqual(CALL, "call")
```

- [ ] **Step 2: Run test to verify it fails**

Run (depuis `api`) : `uv run python -m unittest discover -s src/unittest/python -p test_interfaces.py`
Expected: `ModuleNotFoundError: No module named 'ycappuccino.api.endpoints_service'`.

- [ ] **Step 3: Implement**

`api/src/main/python/ycappuccino/api/endpoints_service.py` :

```python
"""
api.endpoints_service: calling a named service, independent of any transport.

Reuses endpoints_storage's error family (NotAuthenticated, Forbidden, NotFound, InvalidRequest)
and its IAuthorization port: services and items share the same authorization mechanism.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ycappuccino.api.core_base import YCappuccinoComponent

# action checked by IAuthorization for a secure service
CALL = "call"


@dataclass
class ServiceResult:
    """result of a service call"""
    body: Any
    headers: dict = field(default_factory=dict)


class IExposedService(YCappuccinoComponent, ABC):
    """a named action, published under its name"""

    name: str = ""
    secure: bool = True

    @abstractmethod
    async def call(
        self, method: str, extra_path: list, params: dict, body: Any, subject: Optional[dict]
    ) -> ServiceResult:
        """handle the request; raise NotFound (endpoints_storage) for an unsupported method/extra_path"""


class IServiceEndpoint(YCappuccinoComponent, ABC):
    """finds a service by name and dispatches to it, applying its authorization"""

    @abstractmethod
    async def call(
        self, name: str, method: str, extra_path: list, params: dict, body: Any, subject: Optional[dict]
    ) -> ServiceResult:
        """NotFound if no service has this name; NotAuthenticated/Forbidden if it is secure and refused"""
```

- [ ] **Step 4: Run tests to verify they pass**

Run (depuis `api`) : `uv run python -m unittest discover -s src/unittest/python`
Expected: `OK`.

---

### Task 2: endpoints_service, projet uv et `ServiceEndpoint`

**Files:**
- Modify: `endpoints_service/pyproject.toml` (tout le fichier), `endpoints_service/.gitignore` (tout le fichier)
- Modify: `endpoints_service/src/main/python/ycappuccino/endpoints_service/__init__.py` (tout le fichier)
- Delete (`git rm`) : `build.py`, `setup.py`, `example/__init__.py`, `src/main/python/ycappuccino/endpoints_services/` (tout le dossier legacy), `src/unittest/`
- Create: `endpoints_service/src/main/python/ycappuccino/endpoints_service/endpoint.py`
- Create: `endpoints_service/src/unittest/python/service_fixtures.py`
- Test: `endpoints_service/src/unittest/python/test_endpoint.py`

**Interfaces:**
- Consumes (Task 1) : `CALL`, `ServiceResult`, `IExposedService`, `IServiceEndpoint`. `ycappuccino.api.endpoints_storage` : `IAuthorization`, `NotAuthenticated`, `Forbidden`, `NotFound`.
- Produces:
  - `ServiceEndpoint(services: list[IExposedService], authorizations: list[IAuthorization])` implémentant `IServiceEndpoint`.
  - fixtures : `FakeExposedService(name, secure=True)` (`.calls`, `.error`, `.result` par défaut `ServiceResult(body={"ok": True})`), `FakeAuthorization(allowed=("*",))` (même forme que celle d'`endpoints_storage`, recopiée ici pour ne pas dépendre du paquet de test d'un autre dépôt), `ALICE = {"sub": "alice", "tid": "acme"}`.

- [ ] **Step 1: Replace the PyBuilder project**

```bash
cd endpoints_service
git rm -q -r build.py setup.py example/__init__.py src/main/python/ycappuccino/endpoints_services src/unittest
mkdir -p src/unittest/python
```

`endpoints_service/pyproject.toml` :

```toml
[project]
name = "ycappuccino-endpoints-service"
version = "0.1.0"
description = "YCappuccino endpoints_service: calling a named service, independent of any transport"
requires-python = ">=3.10"
dependencies = [
    "ycappuccino-api",
    "ycappuccino-core",
]

[build-system]
requires = ["uv_build>=0.12.13,<0.13"]
build-backend = "uv_build"

[tool.uv.build-backend]
module-name = "ycappuccino.endpoints_service"
module-root = "src/main/python"

[tool.uv.sources]
ycappuccino-api = { path = "../api", editable = true }
ycappuccino-core = { path = "../core", editable = true }
```

`endpoints_service/.gitignore` :

```
data
.venv
__pycache__
dist
```

`endpoints_service/src/main/python/ycappuccino/endpoints_service/__init__.py` :

```python
"""calling a named service, independent of any transport"""
```

Run (depuis `endpoints_service`) : `uv sync`
Expected: environnement créé, `ycappuccino-api` et `ycappuccino-core` installés en éditable.

- [ ] **Step 2: Write the fixtures**

`endpoints_service/src/unittest/python/service_fixtures.py` :

```python
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
```

- [ ] **Step 3: Write the failing test**

`endpoints_service/src/unittest/python/test_endpoint.py` :

```python
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
```

- [ ] **Step 4: Run test to verify it fails**

Run (depuis `endpoints_service`) : `uv run python -m unittest discover -s src/unittest/python`
Expected: `ModuleNotFoundError: No module named 'ycappuccino.endpoints_service.endpoint'`.

- [ ] **Step 5: Implement**

`endpoints_service/src/main/python/ycappuccino/endpoints_service/endpoint.py` :

```python
"""
ServiceEndpoint: finds a named service and dispatches to it, applying its authorization.
"""

import logging

from ycappuccino.api.endpoints_service import CALL, IExposedService, IServiceEndpoint
from ycappuccino.api.endpoints_storage import Forbidden, IAuthorization, NotAuthenticated, NotFound

_logger = logging.getLogger(__name__)


class ServiceEndpoint(IServiceEndpoint):

    def __init__(self, services: list[IExposedService], authorizations: list[IAuthorization]):
        self._services = services
        self._authorizations = authorizations

    async def start(self):
        pass

    async def stop(self):
        pass

    async def call(self, name, method, extra_path, params, body, subject):
        service = self._find(name)
        await self._check(service, subject)
        return await service.call(method, extra_path, params, body, subject)

    def _find(self, name):
        for service in list(self._services):
            if service.name == name:
                return service
        raise NotFound(f"unknown service {name}")

    async def _check(self, service, subject):
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
```

- [ ] **Step 6: Run tests to verify they pass**

Run (depuis `endpoints_service`) : `uv run python -m unittest discover -s src/unittest/python`
Expected: `OK`.

---

### Task 3: endpoints_service, intégration au framework, exemple et README

**Files:**
- Test: `endpoints_service/src/unittest/python/test_endpoint_framework.py`
- Test: `endpoints_service/src/unittest/python/test_readme.py`
- Create: `endpoints_service/README.md`
- Modify: `endpoints_service/example/conf/application.yml` (tout le fichier)
- Create: `endpoints_service/example/library/__init__.py` (vide), `endpoints_service/example/library/echo.py`

**Interfaces:**
- Consumes (Task 2) : `ServiceEndpoint`, fixtures.

- [ ] **Step 1: Write the integration test**

`endpoints_service/src/unittest/python/test_endpoint_framework.py` :

```python
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
```

- [ ] **Step 2: Run the integration test**

Run (depuis `endpoints_service`) : `uv run python -m unittest discover -s src/unittest/python -p test_endpoint_framework.py`
Expected: `OK`, 1 test.

- [ ] **Step 3: Write the README**

`endpoints_service/README.md` :

````markdown
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

`name` identifie le service ; `secure` (par défaut `True`) exige un sujet et une autorisation. `call` reçoit le verbe HTTP, les segments de chemin après le nom du service (`extra_path`, une liste), la query string, le corps décodé et le sujet. Il lève `NotFound` (`ycappuccino.api.endpoints_storage`) pour une combinaison non supportée.

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
````

- [ ] **Step 4: Write the README test**

`endpoints_service/src/unittest/python/test_readme.py` :

```python
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
```

- [ ] **Step 5: Run the README test**

Run (depuis `endpoints_service`) : `uv run python -m unittest discover -s src/unittest/python -p test_readme.py`
Expected: `OK`, 2 tests. Si un exemple ne fonctionne pas tel quel, corriger le README **et** le test pour qu'ils restent identiques.

- [ ] **Step 6: Rebuild the example**

`endpoints_service/example/conf/application.yml` :

```yaml
---
name: services-demo
bundle_prefix:
  - ycappuccino.endpoints_service
  - library
config:
  http_server:
    active: false
```

`endpoints_service/example/library/__init__.py` : fichier vide.

`endpoints_service/example/library/echo.py` : identique à l'exemple `Echo` de la section « Déclarer un service » du README.

- [ ] **Step 7: Run all endpoints_service tests**

Run (depuis `endpoints_service`) : `uv run python -m unittest discover -s src/unittest/python`
Expected: `OK`.

---

### Task 4: http_server, route `/services`

**Files:**
- Modify: `http_server/src/main/python/ycappuccino/http_server/servlet.py` (constructeur, `_route`, `_ok`, ajout de `_route_services`)
- Modify: `http_server/src/unittest/python/servlet_fixtures.py` (`FakeServiceEndpoint`, `create_servlet` gagne `services`)
- Modify: `http_server/src/unittest/python/test_servlet.py` (ajout d'une classe)

**Interfaces:**
- Consumes (Task 1) : `ycappuccino.api.endpoints_service.IServiceEndpoint`, `ServiceResult`.
- Produces:
  - `ApiServlet.__init__` gagne un paramètre `services: list[IServiceEndpoint]`, après `authentications` et avant `path`.
  - `_ok(status, payload, headers=None) -> HttpResponse` : `headers or {}` est fusionné dans `HttpResponse.headers` (comportement inchangé pour les appelants existants).
  - `_route_services(method, rest, params, fields, subject)` : route `/services/<nom>[/<segment>...]` vers `services[0].call(...)` ; `404` si `rest` est vide ou si `services` est vide.
  - fixture `FakeServiceEndpoint()` (`.calls`, `.error`, `.result` par défaut `ServiceResult(body={"ok": True}, headers={})`) ; `create_servlet(subject=None, authentications=None, services=None)` — `services` par défaut `[]`, **le tuple renvoyé reste `(servlet, crud, drafts, catalog)` inchangé**, pour ne pas casser les classes de test existantes qui le déstructurent déjà ; un test qui a besoin du faux `IServiceEndpoint` le construit lui-même et le passe en paramètre, sans attendre que `create_servlet` le renvoie.

- [ ] **Step 1: Write the failing test**

Dans `http_server/src/unittest/python/servlet_fixtures.py`, remplacer la ligne d'import :

```python
from ycappuccino.api.endpoints_storage import ICrud, IDrafts, IItemCatalog, NotFound
```

par :

```python
from ycappuccino.api.endpoints_service import IServiceEndpoint, ServiceResult
from ycappuccino.api.endpoints_storage import ICrud, IDrafts, IItemCatalog, NotFound
```

Ajouter, après `FakeAuthentication` :

```python
class FakeServiceEndpoint(IServiceEndpoint):

    def __init__(self):
        self.calls = []
        self.error = None
        self.result = ServiceResult(body={"ok": True})

    async def call(self, name, method, extra_path, params, body, subject):
        self.calls.append((name, method, extra_path, params, body, subject))
        if self.error is not None:
            raise self.error
        return self.result

    async def start(self):
        pass

    async def stop(self):
        pass
```

Remplacer la signature de `create_servlet` :

```python
def create_servlet(subject=None, authentications=None):
```

par :

```python
def create_servlet(subject=None, authentications=None, services=None):
```

et la ligne de construction :

```python
    return ApiServlet(crud, drafts, catalog, authentications), crud, drafts, catalog
```

par :

```python
    return ApiServlet(crud, drafts, catalog, authentications, services or []), crud, drafts, catalog
```

Ajouter à `http_server/src/unittest/python/test_servlet.py`, avant `if __name__ == "__main__":` :

```python
class TestServiceRoutes(unittest.IsolatedAsyncioTestCase):

    async def test_call_forwards_method_extra_path_params_body_and_subject(self):
        services = FakeServiceEndpoint()
        servlet, _, _, _ = create_servlet(subject=SUBJECT, services=[services])

        response = await servlet.handle(
            request(method="POST", sub_path="/services/echo/x/y", query={"q": "1"}, body=b'{"msg": "hi"}')
        )

        self.assertEqual(json.loads(response.body)["data"], {"ok": True})
        self.assertEqual(
            services.calls, [("echo", "POST", ["x", "y"], {"q": "1"}, {"msg": "hi"}, SUBJECT)]
        )

    async def test_result_headers_are_reported_on_the_response(self):
        services = FakeServiceEndpoint()
        services.result = ServiceResult(body={}, headers={"set-cookie": "a=b"})
        servlet, _, _, _ = create_servlet(services=[services])

        response = await servlet.handle(request(method="POST", sub_path="/services/login"))

        self.assertEqual(response.headers.get("set-cookie"), "a=b")

    async def test_no_service_name_is_not_found(self):
        servlet, _, _, _ = create_servlet(services=[FakeServiceEndpoint()])

        response = await servlet.handle(request(sub_path="/services"))

        self.assertEqual(response.status, 404)

    async def test_no_service_endpoint_registered_is_not_found(self):
        servlet, _, _, _ = create_servlet(services=[])

        response = await servlet.handle(request(sub_path="/services/echo"))

        self.assertEqual(response.status, 404)

    async def test_service_errors_are_mapped(self):
        from ycappuccino.api.endpoints_storage import Forbidden

        services = FakeServiceEndpoint()
        services.error = Forbidden("no")
        servlet, _, _, _ = create_servlet(services=[services])

        response = await servlet.handle(request(method="POST", sub_path="/services/secret"))

        self.assertEqual(response.status, 403)
```

Dans `http_server/src/unittest/python/test_servlet.py`, remplacer les deux lignes d'import :

```python
from servlet_fixtures import FakeAuthentication, SUBJECT, create_servlet

from ycappuccino.api.http import HttpRequest
```

par :

```python
from servlet_fixtures import FakeAuthentication, FakeServiceEndpoint, SUBJECT, create_servlet

from ycappuccino.api.endpoints_service import ServiceResult
from ycappuccino.api.http import HttpRequest
```

- [ ] **Step 2: Run test to verify it fails**

Run (depuis `http_server`) : `uv run python -m unittest discover -s src/unittest/python -p test_servlet.py`
Expected: `TypeError: ApiServlet.__init__() missing 1 required positional argument: 'services'` (ou équivalent), puisque `servlet.py` n'a pas encore le nouveau paramètre.

- [ ] **Step 3: Implement**

Dans `http_server/src/main/python/ycappuccino/http_server/servlet.py`, ajouter l'import :

```python
from ycappuccino.api.endpoints_service import IServiceEndpoint
```

Remplacer le constructeur :

```python
    def __init__(
        self,
        crud: ICrud,
        drafts: IDrafts,
        catalog: IItemCatalog,
        authentications: list[IAuthentication],
        path: str = "/api",
    ):
        self._crud = crud
        self._drafts = drafts
        self._catalog = catalog
        self._authentications = authentications
```

par :

```python
    def __init__(
        self,
        crud: ICrud,
        drafts: IDrafts,
        catalog: IItemCatalog,
        authentications: list[IAuthentication],
        services: list[IServiceEndpoint],
        path: str = "/api",
    ):
        self._crud = crud
        self._drafts = drafts
        self._catalog = catalog
        self._authentications = authentications
        self._services = services
```

Remplacer :

```python
        if family == "items":
            return await self._route_items(method, rest, subject)
        raise NotFound("not found")
```

par :

```python
        if family == "items":
            return await self._route_items(method, rest, subject)
        if family == "services":
            return await self._route_services(method, rest, params, fields, subject)
        raise NotFound("not found")

    async def _route_services(self, method, rest, params, fields, subject):
        services = list(self._services)
        if not rest or not services:
            raise NotFound("not found")
        name, extra_path = rest[0], rest[1:]
        result = await services[0].call(name, method, extra_path, params, fields, subject)
        return _ok(200, result.body, headers=result.headers)
```

Remplacer :

```python
def _ok(status, payload) -> HttpResponse:
    if isinstance(payload, dict) and "items" in payload and "total" in payload:
        meta = {"type": "array", "size": payload["total"]}
        data = payload["items"]
    elif isinstance(payload, list):
        meta = {"type": "array", "size": len(payload)}
        data = payload
    elif payload is None:
        meta = {"type": "object"}
        data = {}
    else:
        meta = {"type": "object", "size": 1}
        data = payload
    body = json.dumps({"status": status, "meta": meta, "data": data}).encode()
    return HttpResponse(status=status, body=body, content_type="application/json")
```

par :

```python
def _ok(status, payload, headers=None) -> HttpResponse:
    if isinstance(payload, dict) and "items" in payload and "total" in payload:
        meta = {"type": "array", "size": payload["total"]}
        data = payload["items"]
    elif isinstance(payload, list):
        meta = {"type": "array", "size": len(payload)}
        data = payload
    elif payload is None:
        meta = {"type": "object"}
        data = {}
    else:
        meta = {"type": "object", "size": 1}
        data = payload
    body = json.dumps({"status": status, "meta": meta, "data": data}).encode()
    return HttpResponse(status=status, body=body, content_type="application/json", headers=dict(headers or {}))
```

- [ ] **Step 4: Run tests to verify they pass**

Run (depuis `http_server`) : `uv run python -m unittest discover -s src/unittest/python`
Expected: `OK`.

---

### Task 5: http_server, intégration réelle, README, CLAUDE.md et vérification finale

**Files:**
- Modify: `http_server/src/unittest/python/test_http_server_framework.py` (ajout d'un test)
- Modify: `http_server/README.md` (table de routage, section services)
- Modify: `CLAUDE.md` (racine du workspace)

**Interfaces:**
- Consumes (Task 4) : la route `/services` réelle. (Task 2/3 d'`endpoints_service`) : `ServiceEndpoint`, un service exemple.

- [ ] **Step 1: Add a real HTTP call to /api/services/... in the integration test**

Dans `http_server/src/unittest/python/test_http_server_framework.py`, ajouter `ycappuccino.endpoints_service` au `bundle_prefix` de `APPLICATION`, et ajouter au module `PACKAGE/books.py` un second fichier `PACKAGE/echo.py` :

```python
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
```

Ajouter, dans `TestHttpServerInFramework`, avant `if __name__ == "__main__":` :

```python
    def test_service_route(self):
        status, body = self.call("POST", "/api/services/echo", body=b'{"msg": "hi"}')

        self.assertEqual(status, 200)
        self.assertEqual(body["data"], {"echo": {"msg": "hi"}})
```

- [ ] **Step 2: Run the integration test**

Run (depuis `http_server`) : `uv run python -m unittest discover -s src/unittest/python -p test_http_server_framework.py`
Expected: `OK`, 4 tests.

- [ ] **Step 3: Update the README**

Dans `http_server/README.md`, ajouter au tableau des routes, après la ligne `/api/items/<pluriel>/empty` :

```markdown
| GET/POST/PUT/DELETE | `/api/services/<nom>[/<segment>...]` | `IServiceEndpoint.call` (voir `endpoints_service`) |
```

Ajouter, avant la section « Authentification », un court paragraphe :

```markdown
## Services

`/api/services/<nom>` route vers un `IExposedService` publié par `endpoints_service`. Sans `endpoints_service` chargé, ces routes répondent `404`. Voir le [README d'endpoints_service](../endpoints_service/README.md) pour déclarer un service.
```

- [ ] **Step 4: Update CLAUDE.md**

Dans `CLAUDE.md`, remplacer :

```markdown
- `http_server` → `ycappuccino.http_server`: native HTTP adapter, a single `ApiServlet` (`ycappuccino.api.http.IHttpServlet`) routing to `endpoints_storage`'s use cases, subject decoded through the `IAuthentication` port (`api/http_server.py`). See `http_server/README.md`.
- The others are feature layers not yet migrated to the new framework: `endpoints_service`, `hosts`, `permissions_app`, `remote`, `scheduler`, `scripts`, `swagger`, `component-creator`.
```

par :

```markdown
- `http_server` → `ycappuccino.http_server`: native HTTP adapter, a single `ApiServlet` (`ycappuccino.api.http.IHttpServlet`) routing to `endpoints_storage`'s use cases and, when loaded, `endpoints_service`'s, subject decoded through the `IAuthentication` port (`api/http_server.py`). See `http_server/README.md`.
- `endpoints_service` → `ycappuccino.endpoints_service`: transport-independent `IServiceEndpoint` calling named `IExposedService` components, authorized through the same `IAuthorization` port as `endpoints_storage` (contract in `api/endpoints_service.py`). See `endpoints_service/README.md`.
- The others are feature layers not yet migrated to the new framework: `hosts`, `permissions_app`, `remote`, `scheduler`, `scripts`, `swagger`, `component-creator`.
```

Remplacer :

```markdown
`api`, `core`, `storage`, `endpoints_storage` and `http_server` are built with **uv** (`pyproject.toml`, `uv_build` backend with `module-root = "src/main/python"` and a dotted `module-name`). `core` depends on `../api`, `storage` on `../api` and `../core`, `endpoints_storage` on `../api`, `../core` and `../storage`, and `http_server` on all four, as editable path sources. The other repos still have PyBuilder `build.py`/`setup.py`.
```

par :

```markdown
`api`, `core`, `storage`, `endpoints_storage`, `http_server` and `endpoints_service` are built with **uv** (`pyproject.toml`, `uv_build` backend with `module-root = "src/main/python"` and a dotted `module-name`). `core` depends on `../api`, `storage` on `../api` and `../core`, `endpoints_storage` on `../api`, `../core` and `../storage`, `http_server` on all four, and `endpoints_service` on `../api` and `../core`, as editable path sources. The other repos still have PyBuilder `build.py`/`setup.py`.
```

Remplacer :

```markdown
Folder, project and package names don't always match: `permissions_app` is project `permissions`, and `endpoints_service` is package `ycappuccino.endpoints_services`.
```

par :

```markdown
Folder, project and package names don't always match: `permissions_app` is project `permissions`.
```

(la mention d'`endpoints_service` disparaît, puisque son paquet est maintenant `ycappuccino.endpoints_service`, identique au nom du dossier)

- [ ] **Step 5: Final verification**

Run, depuis chaque dépôt, dans cet ordre :

```bash
cd api && uv run python -m unittest discover -s src/unittest/python
cd ../core && uv run python -m unittest discover -s src/unittest/python
cd ../storage && uv run python -m unittest discover -s src/unittest/python
cd ../endpoints_storage && uv run python -m unittest discover -s src/unittest/python
cd ../endpoints_service && uv run python -m unittest discover -s src/unittest/python
cd ../http_server && uv run python -m unittest discover -s src/unittest/python
```

Expected: `OK` pour les six dépôts (tests Mongo de `storage` ignorés sans Docker).
