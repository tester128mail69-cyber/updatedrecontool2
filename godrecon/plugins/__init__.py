"""GODRECON plugin support.

External plugins are discovered and loaded by :mod:`godrecon.plugins.loader`.
The :data:`_REGISTRY` dict maps plugin names to their :class:`~godrecon.modules.base.BaseModule`
subclasses after loading.
"""

from __future__ import annotations

from typing import Dict, Type

# Registry populated by load_plugins(); maps plugin name -> plugin class.
_REGISTRY: Dict[str, Type] = {}
