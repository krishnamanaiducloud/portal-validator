from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Mapping


class AuthenticationConfigurationError(ValueError):
    """Raised for invalid authentication configuration without exposing secrets."""


@dataclass(frozen=True)
class CredentialScopePolicy:
    """The sole policy deciding where validator-managed credentials may be sent."""

    approved_hosts: frozenset[str]

    def allows(self, destination_host: str) -> bool:
        return destination_host.strip().lower().rstrip(".") in self.approved_hosts


class AuthenticationProvider:
    mode = "none"

    def headers(self) -> dict[str, str]:
        return {}


class NoAuthenticationProvider(AuthenticationProvider):
    mode = "none"


@dataclass(frozen=True, repr=False)
class BasicAuthenticationProvider(AuthenticationProvider):
    username: str
    password: str
    mode = "basic"

    def headers(self) -> dict[str, str]:
        if not self.username or not self.password:
            raise AuthenticationConfigurationError(
                "Basic authentication requires username and password"
            )
        value = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        return {"Authorization": f"Basic {value}"}


@dataclass(frozen=True, repr=False)
class BearerTokenProvider(AuthenticationProvider):
    token: str
    mode = "bearer"

    def headers(self) -> dict[str, str]:
        token = self.token.strip()
        if token.lower() == "bearer":
            token = ""
        elif token[:7].lower() == "bearer ":
            token = token[7:].strip()
        if not token:
            raise AuthenticationConfigurationError("Bearer authentication requires a token")
        return {"Authorization": f"Bearer {token}"}


@dataclass(frozen=True, repr=False)
class CustomHeaderProvider(AuthenticationProvider):
    configured_headers: Mapping[str, str]
    mode = "headers"

    def headers(self) -> dict[str, str]:
        if not self.configured_headers:
            raise AuthenticationConfigurationError(
                "Custom-header authentication requires at least one header"
            )
        return dict(self.configured_headers)


class CookieAuthenticationProvider(AuthenticationProvider):
    mode = "cookies"


class SessionAuthenticationProvider(AuthenticationProvider):
    mode = "storage_state"


@dataclass(frozen=True, repr=False)
class AuthenticationManager:
    """Composes a provider with credential scope and deterministic precedence."""

    provider: AuthenticationProvider
    scope: CredentialScopePolicy

    @property
    def mode(self) -> str:
        return self.provider.mode

    @property
    def credential_host_count(self) -> int:
        return len(self.scope.approved_hosts)

    def configured_headers(self) -> dict[str, str]:
        return self.provider.headers()

    def headers_for_request(
        self,
        request_headers: Mapping[str, str],
        destination_host: str,
    ) -> dict[str, str]:
        """Apply owned headers only in credential scope and remove them elsewhere.

        In bearer/basic/custom-header modes, configured headers are validator-owned,
        so their values deterministically replace an existing header on an approved
        destination. Session/no-auth modes own no headers and therefore never alter
        application-generated Authorization headers.
        """
        headers = dict(request_headers)
        configured = self.configured_headers()
        owned_names = {name.lower() for name in configured}
        for name in list(headers):
            if name.lower() in owned_names:
                headers.pop(name, None)
        if self.scope.allows(destination_host):
            headers.update(configured)
        return headers


def build_authentication_manager(
    *,
    mode: str,
    credential_hosts: set[str],
    username: str | None = None,
    password: str | None = None,
    token: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> AuthenticationManager:
    providers: dict[str, AuthenticationProvider] = {
        "none": NoAuthenticationProvider(),
        "cookies": CookieAuthenticationProvider(),
        "storage_state": SessionAuthenticationProvider(),
    }
    if mode == "basic":
        provider: AuthenticationProvider = BasicAuthenticationProvider(
            username or "", password or ""
        )
    elif mode == "bearer":
        provider = BearerTokenProvider(token or "")
    elif mode == "headers":
        provider = CustomHeaderProvider(headers or {})
    elif mode in providers:
        provider = providers[mode]
    else:
        raise AuthenticationConfigurationError("Authentication mode is not supported")
    normalized_hosts = frozenset(
        host.strip().lower().rstrip(".") for host in credential_hosts if host.strip()
    )
    return AuthenticationManager(provider, CredentialScopePolicy(normalized_hosts))
