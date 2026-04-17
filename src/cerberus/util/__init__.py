"""Compatibility package for Cerberus utility modules.

This package exists so imports like ``cerberus.util.config`` work, while the
project still has a legacy ``cerberus/util.py`` module that many call sites
import directly as ``cerberus.util``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


_LEGACY_UTIL_PATH = Path(__file__).resolve().parent.parent / "util.py"
_LEGACY_SPEC = importlib.util.spec_from_file_location("cerberus._legacy_util", _LEGACY_UTIL_PATH)

if _LEGACY_SPEC is None or _LEGACY_SPEC.loader is None:
	raise ImportError(f"Unable to load legacy utility module from {_LEGACY_UTIL_PATH}")

_legacy_util = importlib.util.module_from_spec(_LEGACY_SPEC)
sys.modules[_LEGACY_SPEC.name] = _legacy_util
_LEGACY_SPEC.loader.exec_module(_legacy_util)

for _name, _value in vars(_legacy_util).items():
	if _name.startswith("__") and _name not in {"__doc__", "__all__"}:
		continue
	globals()[_name] = _value

__all__ = getattr(
	_legacy_util,
	"__all__",
	[name for name in vars(_legacy_util) if not name.startswith("_")],
)
