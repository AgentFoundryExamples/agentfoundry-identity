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
"""Single source of truth for service version.

This module defines the canonical version string used throughout the Identity Service,
including:
- Health endpoint responses
- Package metadata (pyproject.toml)
- API documentation

To bump the version:
1. Update __version__ in this file
2. Update CHANGELOG.md with release notes
3. Verify health endpoint reports new version
4. Tag the release in git

Follows Semantic Versioning (https://semver.org/):
- MAJOR: Breaking API changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible
"""

__version__ = "0.2.0"
