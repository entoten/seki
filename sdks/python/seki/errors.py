"""Error types for the seki Python SDK."""

from __future__ import annotations


class SekiAPIError(Exception):
    """RFC 7807 Problem Details error from the seki API."""

    def __init__(
        self,
        *,
        status: int,
        title: str = "",
        detail: str = "",
        type: str = "about:blank",
    ) -> None:
        self.status = status
        self.title = title or f"HTTP {status}"
        self.detail = detail
        self.type = type
        if detail:
            msg = f"{self.title}: {detail} (HTTP {status})"
        else:
            msg = f"{self.title} (HTTP {status})"
        super().__init__(msg)

    @classmethod
    def from_response(cls, status: int, body: dict) -> SekiAPIError:
        """Create from a parsed JSON response body."""
        return cls(
            status=status,
            title=body.get("title", ""),
            detail=body.get("detail", ""),
            type=body.get("type", "about:blank"),
        )

    @property
    def is_not_found(self) -> bool:
        return self.status == 404

    @property
    def is_conflict(self) -> bool:
        return self.status == 409
