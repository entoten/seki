"""Typed dictionaries for seki API request and response payloads."""

from __future__ import annotations

from typing import Any, TypedDict


# ---------------------------------------------------------------------------
# Request types
# ---------------------------------------------------------------------------

class CreateUserInput(TypedDict, total=False):
    email: str          # required
    name: str
    metadata: dict[str, Any]


class UpdateUserInput(TypedDict, total=False):
    email: str
    name: str
    disabled: bool
    metadata: dict[str, Any]


class CreateOrgInput(TypedDict, total=False):
    slug: str           # required
    name: str           # required
    domains: list[str]
    metadata: dict[str, Any]


class UpdateOrgInput(TypedDict, total=False):
    name: str
    slug: str
    domains: list[str]
    metadata: dict[str, Any]


class AddMemberInput(TypedDict, total=False):
    user_id: str        # required
    role: str


class UpdateMemberRoleInput(TypedDict):
    role: str


class CreateRoleInput(TypedDict):
    name: str
    permissions: list[str]


class UpdateRoleInput(TypedDict):
    permissions: list[str]


class CreateClientInput(TypedDict, total=False):
    id: str             # required
    name: str           # required
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    pkce_required: bool


class ImportUserInput(TypedDict, total=False):
    email: str          # required
    display_name: str
    password_hash: str
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Response types
# ---------------------------------------------------------------------------

class User(TypedDict):
    id: str
    email: str
    name: str
    email_verified: bool
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


class Organization(TypedDict):
    id: str
    slug: str
    name: str
    domains: list[str]
    created_at: str
    updated_at: str


class Member(TypedDict):
    user_id: str
    org_id: str
    role: str
    joined_at: str


class Role(TypedDict):
    id: str
    name: str
    permissions: list[str]


class OAuthClient(TypedDict):
    id: str
    name: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    pkce_required: bool
    created_at: str
    updated_at: str


class AuditEntry(TypedDict):
    id: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str
    metadata: dict[str, Any]
    timestamp: str


class ImportError_(TypedDict):
    """A single error in an import batch (named with trailing _ to avoid shadowing builtins)."""
    line: int
    email: str
    error: str


class ImportResult(TypedDict):
    created: int
    skipped: int
    total: int
    errors: list[ImportError_]


class ListResult(TypedDict):
    data: list[Any]
    next_cursor: str


class ProblemDetail(TypedDict):
    type: str
    title: str
    status: int
    detail: str
