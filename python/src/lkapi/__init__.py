#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# Distributed under the MIT License (see LICENSE).
#
"""
Python client for the Lightkeeper API.

The top level package exposes the primary entry points; the submodules remain available for
advanced use:
  + **client**: request data grids from a Lightkeeper environment.
  + **credential**: secure storage and retrieval of API credentials.
  + **parser**: URL handling and conversion of API JSON responses to pandas data frames.
"""
from importlib.metadata import PackageNotFoundError, version

from .client import get_grid_data
from .credential import (
    CredentialManager,
    get_auth_token,
    get_credential_manager,
)
from .parser import (
    build_api_url,
    parse_api_url,
    lk_api_response_to_frames,
)

try:
    __version__ = version("lkapi")
except PackageNotFoundError:
    # running from a source tree without an installed distribution
    __version__ = "0.3.0"

__all__ = [
    "get_grid_data",
    "CredentialManager",
    "get_auth_token",
    "get_credential_manager",
    "build_api_url",
    "parse_api_url",
    "lk_api_response_to_frames",
    "__version__",
]
