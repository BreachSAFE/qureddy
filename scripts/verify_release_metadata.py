#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Verify source release metadata before building distributions."""

from __future__ import annotations

from release_support import verify_release_metadata

if __name__ == "__main__":
    print(verify_release_metadata())
