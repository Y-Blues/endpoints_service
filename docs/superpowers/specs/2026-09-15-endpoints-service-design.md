# endpoints_service natif : design

Date : 2026-09-15. Sous-projet 2 de la reprise des dépôts YCappuccino, après `core`, `api`, `storage`, `endpoints_storage`, `http_server`.

## Objectif

`endpoints_service` fournit le cas d'usage d'appel de services : un service natif expose une action (par exemple « login », « exécuter un script ») indépendamment du transport ; `IServiceEndpoint` le trouve par son nom et le sécurise ; `http_server` route `/api/services/...` vers lui. Contrairement à `endpoints_storage`, un service n'a ni pluriel, ni schéma, ni brouillon : c'est une action, pas une ressource CRUD.

## Décisions

| Sujet | Décision |
|---|---|
| Style | Composants natifs, aucun décorateur ; mêmes conventions qu'`endpoints_storage` (listes vivantes, fermé par défaut) |
| Dispatch d'un service | Une seule méthode `async call(method, extra_path, params, body, subject) -> ServiceResult` par service ; il décide lui-même ce qu'il supporte, lève `NotFound` sinon |
| Sécurité | Réutilise `IAuthorization` et la famille d'erreurs `CrudError` d'`endpoints_storage`, avec l'action `CALL = "call"` et la ressource = nom du service |
| En-têtes de réponse | `ServiceResult.headers` (ex. `Set-Cookie`) ; `endpoints_storage` n'en a pas besoin, mais `LoginCookieService` legacy en a un besoin réel |
| Chemin supplémentaire | `extra_path` est déjà découpé en segments (liste de `str`), comme le fait `ApiServlet` pour ses propres routes ; pas de moteur de gabarits d'URL |
| Catalogue de services | Hors périmètre : pas de `list_services`, ajouté plus tard si `swagger` en a besoin |
| Paquet | `ycappuccino.endpoints_service`, projet `ycappuccino-endpoints-service` (legacy : paquet `ycappuccino.endpoints_services`, projet `endpoints_service`) |

## 1. Contrat dans `api` (`ycappuccino.api.endpoints_service`, nouveau module)

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

`method` est le verbe HTTP (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`) ; `params` est la query string de la requête (dict de texte) ; `body` est le corps JSON décodé, ou `None`.

## 2. `ServiceEndpoint` (`endpoints_service/.../endpoint.py`)

```python
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

- **`services: list[IExposedService]`** : liste vivante ; un nom en double garde le premier trouvé (aucun déploiement réel n'en enregistre deux, YAGNI de ne pas se prémunir davantage).
- **`_check`** reprend exactement les étapes 3 à 6 de la vérification d'`endpoints_storage.Access.check` (action non sécurisée → passe sans appel ; sécurisée et sujet absent → `NotAuthenticated` ; sécurisée et aucune `IAuthorization` → `Forbidden`, journalisé ; sinon décision d'`is_authorized`), simplifiée puisqu'il n'y a ni item, ni `isWritable`, ni item abstrait à vérifier au préalable.

## 3. Raccordement dans `http_server`

`ApiServlet` gagne un paramètre `services: list[IServiceEndpoint]`, liste vivante comme `authentications` — `endpoints_service` est un bundle séparé d'`http_server` ; rien ne garantit qu'il soit chargé avant lui selon l'ordre de `bundle_prefix`, exactement comme `permissions_app` (qui fournit `IAuthorization`) vis-à-vis d'`endpoints_storage`. Une dépendance optionnelle simple (`Optional[IServiceEndpoint] = None`) ne serait relue qu'à la validation du composant (voir `core`) et resterait `None` pour toujours si `endpoints_service` démarre après `http_server` — le même piège déjà rencontré et corrigé pour `authorizations` dans `endpoints_storage`.

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
```

Nouvelle famille de route, ajoutée à `_route` :

```python
if family == "services":
    return await self._route_services(method, rest, params, fields, subject)
```

```python
async def _route_services(self, method, rest, params, fields, subject):
    services = list(self._services)
    if not rest or not services:
        raise NotFound("not found")
    name, extra_path = rest[0], rest[1:]
    result = await services[0].call(name, method, extra_path, params, fields, subject)
    return _ok(200, result.body, headers=result.headers)
```

`_ok` gagne un paramètre optionnel `headers: dict | None = None`, fusionné dans les en-têtes de la `HttpResponse` (comportement inchangé pour tous les appelants existants, qui ne passent pas `headers`).

| Méthode | Chemin | Appel |
|---|---|---|
| GET/POST/PUT/DELETE | `/services/<nom>[/<segment>...]` | `services.call(nom, méthode, segments_restants, params, fields, subject)` |

Sans `endpoints_service` chargé (`services` vide), `/api/services/...` reste `404`, comme documenté dans le README d'`http_server` (« hors périmètre » de son propre sous-projet).

## 4. Packaging et exemple

```
endpoints_service/
  pyproject.toml
  README.md
  example/conf/application.yml
  example/library/__init__.py
  example/library/echo.py
  src/main/python/ycappuccino/endpoints_service/
    __init__.py
    endpoint.py
  src/unittest/python/...
```

- **`pyproject.toml`** (uv, `uv_build`) : projet `ycappuccino-endpoints-service`, module `ycappuccino.endpoints_service`, racine `src/main/python`. Dépendances : `ycappuccino-api`, `ycappuccino-core` en sources locales éditables (pas de dépendance à `storage`/`endpoints_storage`, ce cas d'usage n'y touche pas).
- **Supprimés** : `build.py`, `setup.py`, le bundle legacy `bundles/endpoint_service.py`, `conf/config.yaml`, les tests vides.
- **`.gitignore`** : `data`, `.venv`, `__pycache__`, `dist`.
- **Exemple** : un service `Echo` (non sécurisé) qui renvoie `{"echo": body}` sur `POST /api/services/echo`, et un service `Secret` (sécurisé, sans `IAuthorization` publiée dans l'exemple) qui montre le `403` fermé par défaut. Chargé avec `ycappuccino.endpoints_service` et `ycappuccino.http_server` dans `bundle_prefix`.
- **README** : mise en place, les deux interfaces, sécurité, exemple de service avec en-tête personnalisé (`Set-Cookie`), test sans framework.

## 5. Tests

| Fichier | Contenu |
|---|---|
| `api` : `test_interfaces.py` | `IExposedService`, `IServiceEndpoint` sont des ABC async ; `ServiceResult` est une dataclass, `headers` par défaut non partagé entre instances |
| `endpoints_service` : `test_endpoint.py` (faux `IExposedService`, faux `IAuthorization`) | service trouvé et appelé avec les bons arguments ; nom inconnu → `NotFound` ; non sécurisé sans sujet → appelé quand même ; sécurisé sans sujet → `NotAuthenticated` ; sécurisé sans `IAuthorization` → `Forbidden` (journalisé) ; sécurisé et refusé → `Forbidden` ; sécurisé et autorisé → appelé ; `IAuthorization` enregistrée après coup → utilisée |
| `test_endpoint_framework.py` | démarrage du framework, `IServiceEndpoint` publié et utilisable |
| `test_readme.py` | les exemples du README s'exécutent |
| `http_server` (modifié) : `test_servlet.py` | nouvelle classe `TestServiceRoutes` : appel simple, `extra_path` non vide, méthode et query transmises, en-têtes de `ServiceResult` reportés sur la réponse, `services` vide → `404`, `IServiceEndpoint` enregistrée après coup → utilisée (même schéma que le test d'intégration d'`endpoints_storage` pour `IAuthorization`), erreurs `CrudError` mappées comme les autres routes |
| `http_server` : `test_http_server_framework.py` (modifié ou nouveau test) | un vrai appel HTTP à `/api/services/<nom>` à travers `endpoints_service` réellement chargé |

## 6. Hors périmètre

- Le catalogue de services (`list_services`) pour `swagger`.
- Les implémentations réelles (`permissions_app`'s login, `scripts`' exécution) : chacune migrée dans son propre sous-projet, en implémentant `IExposedService`.
- La validation de schéma des paramètres/corps d'un service : à la charge de chaque service, comme pour `endpoints_storage`.

## 7. Risques

- **Un service mal écrit peut lever n'importe quelle exception** : elle remonte telle quelle jusqu'à `ApiServlet.handle`, qui la traduit en `500` générique (comportement déjà en place, aucun risque nouveau).
- **`extra_path` sans validation de forme** : chaque service interprète ses propres segments ; une erreur de segments donne un `NotFound` normal si le service la détecte, ou un comportement incorrect si le service ne valide pas — assumé, à la charge de chaque service comme documenté.
