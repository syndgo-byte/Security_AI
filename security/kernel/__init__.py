"""Live Linux host hardening, separate from service source-code scanners."""

# This legacy package takes precedence over the sibling kernel.py on import.
# Expose that implementation while keeping the existing submodules available.
import importlib.util as _util
import sys as _sys
from pathlib import Path as _Path

_spec = _util.spec_from_file_location("security._kernel_impl", _Path(__file__).parent.parent / "kernel.py")
_impl = _util.module_from_spec(_spec)
_sys.modules[_spec.name] = _impl
_spec.loader.exec_module(_impl)
globals().update({name: value for name, value in vars(_impl).items() if not name.startswith("__")})
