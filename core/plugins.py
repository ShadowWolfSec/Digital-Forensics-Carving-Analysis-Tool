from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .models import FileSignature, ValidationResult
from .signatures import SignatureDatabase
from .validators import register_validator


ValidatorFn = Callable[[bytes], ValidationResult]


@dataclass
class PluginDefinition:
    name: str
    signature: FileSignature
    validator_name: str = "validate_generic"
    validator_fn: Optional[ValidatorFn] = None
    metadata_extractor: Optional[Callable[[bytes], Dict]] = None


class ForensicsPlugin:
    """Base class for community plugins."""

    def definition(self) -> PluginDefinition:
        raise NotImplementedError


class PluginManager:
    def __init__(self):
        self._plugins: List[PluginDefinition] = []
        self._metadata_extractors: Dict[str, Callable[[bytes], Dict]] = {}

    @property
    def plugins(self) -> List[PluginDefinition]:
        return list(self._plugins)

    def register(self, plugin: ForensicsPlugin):
        pd = plugin.definition()
        if pd.validator_fn and pd.validator_name:
            register_validator(pd.validator_name, pd.validator_fn)
            pd.signature.validator = pd.validator_name
        if pd.metadata_extractor:
            self._metadata_extractors[pd.signature.id] = pd.metadata_extractor
        self._plugins.append(pd)

    def apply_to_db(self, sig_db: SignatureDatabase):
        for p in self._plugins:
            sig_db.add_custom(p.signature)

    def metadata_extractor_for(self, signature_id: str):
        return self._metadata_extractors.get(signature_id)

    def load_from_dir(self, plugins_dir: str) -> List[str]:
        loaded = []
        root = Path(plugins_dir)
        if not root.exists():
            return loaded
        for pyf in root.glob("*.py"):
            mod = _load_module(pyf)
            if not mod:
                continue
            plugin_cls = getattr(mod, "Plugin", None)
            if plugin_cls is None:
                continue
            instance = plugin_cls()
            if not isinstance(instance, ForensicsPlugin):
                continue
            self.register(instance)
            loaded.append(pyf.stem)
        return loaded


def _load_module(path: Path):
    try:
        spec = importlib.util.spec_from_file_location(path.stem, str(path))
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

