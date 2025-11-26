# ============================================================
# SPDX-License-Identifier: GPL-3.0-or-later
# This program was generated as part of the AgentFoundry project.
# Copyright (C) 2025  John Brosnihan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ============================================================
"""Session store abstraction and in-memory implementation.

This module defines the SessionStore protocol for session persistence
and provides an InMemorySessionStore for development use. The store
enforces expiration and revocation semantics.
"""

import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from uuid import UUID

import structlog

from af_identity_service.models.session import Session

logger = structlog.get_logger(__name__)


class SessionStore(ABC):
    """Abstract base class for session storage.

    Implementations must be thread-safe to avoid race conditions
    in multi-worker environments like Cloud Run.

    The store enforces that expired sessions are treated as inactive
    even if not explicitly revoked, avoiding time-skew bugs.

    Methods:
        create: Create a new session.
        get: Retrieve a session by ID.
        revoke: Revoke a session.
        list_by_user: List all sessions for a user.
    """

    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Create and store a new session.

        Args:
            session: The session to store.

        Returns:
            The stored session.
        """
        pass

    @abstractmethod
    async def get(self, session_id: UUID) -> Session | None:
        """Retrieve a session by ID.

        Returns None if the session is not found. Expired sessions
        are still returned but will have is_expired() == True.

        Args:
            session_id: The session's UUID.

        Returns:
            The Session if found, None otherwise.

        Raises:
            ValueError: If session_id is not a valid UUID.
        """
        pass

    @abstractmethod
    async def revoke(self, session_id: UUID) -> bool:
        """Revoke a session.

        Args:
            session_id: The session's UUID.

        Returns:
            True if the session was found and revoked, False if not found.

        Raises:
            ValueError: If session_id is not a valid UUID.
        """
        pass

    @abstractmethod
    async def list_by_user(
        self, user_id: UUID, include_inactive: bool = False
    ) -> list[Session]:
        """List all sessions for a user.

        Args:
            user_id: The user's UUID.
            include_inactive: If True, includes expired and revoked sessions.
                             If False (default), only returns active sessions.

        Returns:
            A list of sessions for the user.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        pass


class InMemorySessionStore(SessionStore):
    """In-memory implementation of SessionStore.

    This implementation is suitable for development and testing only.
    It stores sessions in memory and uses threading locks for thread-safety.

    WARNING: Data is lost when the process exits. Use a persistent
    implementation (e.g., Redis) for production deployments.

    The store enforces that expired sessions are treated as inactive
    when listing, avoiding time-skew bugs.

    Attributes:
        _sessions: Dictionary mapping session UUIDs to Session instances.
        _user_sessions: Dictionary mapping user UUIDs to sets of session UUIDs.
        _lock: Threading lock for thread-safe operations.
    """

    def __init__(self) -> None:
        """Initialize the in-memory session store."""
        self._sessions: dict[UUID, Session] = {}
        self._user_sessions: dict[UUID, set[UUID]] = {}
        self._lock = threading.Lock()
        logger.info("Initialized in-memory session store (dev-only)")

    async def create(self, session: Session) -> Session:
        """Create and store a new session.

        Args:
            session: The session to store.

        Returns:
            The stored session.
        """
        with self._lock:
            self._sessions[session.session_id] = session
            if session.user_id not in self._user_sessions:
                self._user_sessions[session.user_id] = set()
            self._user_sessions[session.user_id].add(session.session_id)

        logger.info(
            "Session created",
            session_id=str(session.session_id),
            user_id=str(session.user_id),
            expires_at=session.expires_at.isoformat(),
        )
        return session

    async def get(self, session_id: UUID) -> Session | None:
        """Retrieve a session by ID.

        Args:
            session_id: The session's UUID.

        Returns:
            The Session if found, None otherwise.

        Raises:
            ValueError: If session_id is not a valid UUID.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        with self._lock:
            session = self._sessions.get(session_id)

        if session:
            logger.debug(
                "Session found",
                session_id=str(session_id),
                is_active=session.is_active(),
            )
        else:
            logger.debug("Session not found", session_id=str(session_id))

        return session

    async def revoke(self, session_id: UUID) -> bool:
        """Revoke a session.

        Args:
            session_id: The session's UUID.

        Returns:
            True if the session was found and revoked, False if not found.

        Raises:
            ValueError: If session_id is not a valid UUID.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                logger.debug("Session not found for revocation", session_id=str(session_id))
                return False

            revoked_session = session.model_copy(update={"revoked": True})
            self._sessions[session_id] = revoked_session

        logger.info("Session revoked", session_id=str(session_id))
        return True

    async def list_by_user(
        self, user_id: UUID, include_inactive: bool = False
    ) -> list[Session]:
        """List all sessions for a user.

        Args:
            user_id: The user's UUID.
            include_inactive: If True, includes expired and revoked sessions.
                             If False (default), only returns active sessions.

        Returns:
            A list of sessions for the user.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        now = datetime.now(timezone.utc)

        with self._lock:
            session_ids = self._user_sessions.get(user_id, set())
            sessions = [
                self._sessions[sid]
                for sid in session_ids
                if sid in self._sessions
            ]

        if not include_inactive:
            sessions = [s for s in sessions if s.is_active(now)]

        logger.debug(
            "Listed sessions for user",
            user_id=str(user_id),
            count=len(sessions),
            include_inactive=include_inactive,
        )
        return sessions
