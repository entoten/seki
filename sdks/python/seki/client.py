"""Synchronous Python client for the seki Admin API."""

from __future__ import annotations

from typing import Any

import httpx

from .errors import SekiAPIError
from .types import (
    AddMemberInput,
    AuditEntry,
    CreateClientInput,
    CreateOrgInput,
    CreateRoleInput,
    CreateUserInput,
    ImportResult,
    ImportUserInput,
    ListResult,
    Member,
    OAuthClient,
    Organization,
    Role,
    UpdateMemberRoleInput,
    UpdateOrgInput,
    UpdateRoleInput,
    UpdateUserInput,
    User,
)


class SekiClient:
    """Synchronous client for the seki Admin API.

    Uses ``httpx`` for HTTP transport.  Requires Python 3.10+.

    Example::

        from seki import SekiClient

        client = SekiClient("http://localhost:8080", "my-api-key")
        user = client.create_user(email="alice@example.com")
    """

    def __init__(self, base_url: str, api_key: str, **httpx_kwargs: Any) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            **httpx_kwargs,
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> SekiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        # Strip None values from params.
        if params:
            params = {k: v for k, v in params.items() if v is not None}

        resp = self._client.request(method, path, json=json, params=params or None)

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {}
            raise SekiAPIError.from_response(resp.status_code, body)

        if resp.status_code == 204:
            return None

        return resp.json()

    @staticmethod
    def _list_params(
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        p: dict[str, Any] = {}
        if cursor:
            p["cursor"] = cursor
        if limit is not None:
            p["limit"] = limit
        return p

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def create_user(
        self,
        email: str,
        name: str = "",
        *,
        metadata: dict[str, Any] | None = None,
    ) -> User:
        """Create a new user."""
        body: CreateUserInput = {"email": email}
        if name:
            body["name"] = name
        if metadata is not None:
            body["metadata"] = metadata
        return self._request("POST", "/api/v1/users", json=body)

    def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        return self._request("GET", f"/api/v1/users/{user_id}")

    def list_users(
        self,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> ListResult:
        """List users with cursor pagination."""
        return self._request(
            "GET", "/api/v1/users", params=self._list_params(cursor, limit)
        )

    def update_user(self, user_id: str, **kwargs: Any) -> User:
        """Update a user. Pass only fields to change (email, name, disabled, metadata)."""
        body: UpdateUserInput = {
            k: v for k, v in kwargs.items() if k in UpdateUserInput.__annotations__
        }  # type: ignore[assignment]
        return self._request("PATCH", f"/api/v1/users/{user_id}", json=body)

    def delete_user(self, user_id: str) -> None:
        """Delete a user by ID."""
        self._request("DELETE", f"/api/v1/users/{user_id}")

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------

    def create_org(
        self,
        slug: str,
        name: str,
        *,
        domains: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Organization:
        """Create a new organization."""
        body: CreateOrgInput = {"slug": slug, "name": name}
        if domains is not None:
            body["domains"] = domains
        if metadata is not None:
            body["metadata"] = metadata
        return self._request("POST", "/api/v1/orgs", json=body)

    def get_org(self, slug: str) -> Organization:
        """Get an organization by slug."""
        return self._request("GET", f"/api/v1/orgs/{slug}")

    def list_orgs(
        self,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> ListResult:
        """List organizations with cursor pagination."""
        return self._request(
            "GET", "/api/v1/orgs", params=self._list_params(cursor, limit)
        )

    def update_org(self, slug: str, **kwargs: Any) -> Organization:
        """Update an organization. Pass only fields to change (name, slug, domains, metadata)."""
        body: UpdateOrgInput = {
            k: v for k, v in kwargs.items() if k in UpdateOrgInput.__annotations__
        }  # type: ignore[assignment]
        return self._request("PATCH", f"/api/v1/orgs/{slug}", json=body)

    def delete_org(self, slug: str) -> None:
        """Delete an organization by slug."""
        self._request("DELETE", f"/api/v1/orgs/{slug}")

    # ------------------------------------------------------------------
    # Members
    # ------------------------------------------------------------------

    def add_member(self, slug: str, user_id: str, role: str = "") -> Member:
        """Add a member to an organization."""
        body: AddMemberInput = {"user_id": user_id}
        if role:
            body["role"] = role
        return self._request("POST", f"/api/v1/orgs/{slug}/members", json=body)

    def list_members(
        self,
        slug: str,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> ListResult:
        """List members of an organization."""
        return self._request(
            "GET",
            f"/api/v1/orgs/{slug}/members",
            params=self._list_params(cursor, limit),
        )

    def update_member_role(self, slug: str, user_id: str, role: str) -> None:
        """Update a member's role in an organization."""
        body: UpdateMemberRoleInput = {"role": role}
        self._request(
            "PATCH", f"/api/v1/orgs/{slug}/members/{user_id}", json=body
        )

    def remove_member(self, slug: str, user_id: str) -> None:
        """Remove a member from an organization."""
        self._request("DELETE", f"/api/v1/orgs/{slug}/members/{user_id}")

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def create_role(
        self, slug: str, name: str, permissions: list[str]
    ) -> Role:
        """Create a role in an organization."""
        body: CreateRoleInput = {"name": name, "permissions": permissions}
        return self._request(
            "POST", f"/api/v1/orgs/{slug}/roles", json=body
        )

    def list_roles(self, slug: str) -> list[Role]:
        """List all roles in an organization."""
        resp = self._request("GET", f"/api/v1/orgs/{slug}/roles")
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    def update_role(
        self, slug: str, name: str, permissions: list[str]
    ) -> Role:
        """Update a role's permissions."""
        body: UpdateRoleInput = {"permissions": permissions}
        return self._request(
            "PATCH", f"/api/v1/orgs/{slug}/roles/{name}", json=body
        )

    def delete_role(self, slug: str, name: str) -> None:
        """Delete a role from an organization."""
        self._request("DELETE", f"/api/v1/orgs/{slug}/roles/{name}")

    # ------------------------------------------------------------------
    # Audit logs
    # ------------------------------------------------------------------

    def list_audit_logs(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        actor_id: str | None = None,
        action: str | None = None,
    ) -> ListResult:
        """List audit log entries with optional filtering."""
        params = self._list_params(cursor, limit)
        if actor_id:
            params["actor_id"] = actor_id
        if action:
            params["action"] = action
        return self._request("GET", "/api/v1/audit-logs", params=params)

    # ------------------------------------------------------------------
    # OAuth clients
    # ------------------------------------------------------------------

    def create_client(
        self,
        id: str,
        name: str,
        *,
        redirect_uris: list[str] | None = None,
        grant_types: list[str] | None = None,
        scopes: list[str] | None = None,
        pkce_required: bool | None = None,
    ) -> OAuthClient:
        """Create an OAuth client."""
        body: CreateClientInput = {"id": id, "name": name}
        if redirect_uris is not None:
            body["redirect_uris"] = redirect_uris
        if grant_types is not None:
            body["grant_types"] = grant_types
        if scopes is not None:
            body["scopes"] = scopes
        if pkce_required is not None:
            body["pkce_required"] = pkce_required
        return self._request("POST", "/api/v1/clients", json=body)

    def get_client(self, client_id: str) -> OAuthClient:
        """Get an OAuth client by ID."""
        return self._request("GET", f"/api/v1/clients/{client_id}")

    def list_clients(self) -> list[OAuthClient]:
        """List all OAuth clients."""
        resp = self._request("GET", "/api/v1/clients")
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client by ID."""
        self._request("DELETE", f"/api/v1/clients/{client_id}")

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_users(self, users: list[ImportUserInput]) -> ImportResult:
        """Bulk import users (JSON). Max 10,000 per request."""
        return self._request("POST", "/api/v1/import/users", json=users)
