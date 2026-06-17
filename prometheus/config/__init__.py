"""prometheus application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings` — sub-models,
  attribute-accessed off ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`persist_current` — write currently-set env vars to the active file.
"""

from prometheus.config.loader import (
    apply_config_override,
    load_settings,
    persist_current,
)
from prometheus.config.settings import (
    LlmSettings,
    RuntimeSettings,
    Settings,
)


__all__ = [
    "LlmSettings",
    "RuntimeSettings",
    "Settings",
    "apply_config_override",
    "load_settings",
    "persist_current",
]
