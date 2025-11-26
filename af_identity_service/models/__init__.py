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
"""Agent Foundry Identity Models.

This module exports all identity-related Pydantic models that define
the data contracts for the identity service. All datetime fields use
timezone-aware UTC timestamps for serialization consistency.
"""

from af_identity_service.models.github import GitHubIdentity, GitHubOAuthResult
from af_identity_service.models.session import Session
from af_identity_service.models.token import AFTokenIntrospection
from af_identity_service.models.user import AFUser

__all__ = [
    "AFUser",
    "GitHubIdentity",
    "GitHubOAuthResult",
    "Session",
    "AFTokenIntrospection",
]
