import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import yaml


class ConfigManager:
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self._load_config()

    def _get_config_path(self) -> Path:
        if getattr(sys, 'frozen', False):
            base_path = Path(sys.executable).parent
        else:
            base_path = Path(__file__).parent.parent
        return base_path / 'config' / 'settings.yaml'

    def _load_config(self):
        config_path = self._get_config_path()
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f)
        else:
            self._config = self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'app': {
                'name': 'WebSec Toolkit',
                'version': '1.01',
                'language': 'zh_CN',
                'theme': 'dark'
            },
            'gui': {
                'window_size': [1400, 900],
                'sidebar_width': 250
            },
            'database': {
                'type': 'sqlite',
                'path': 'data/websec.db'
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/app.log'
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def save(self):
        config_path = self._get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self._config, f, allow_unicode=True, default_flow_style=False)

    @property
    def app_name(self) -> str:
        return self.get('app.name', 'WebSec Toolkit')

    @property
    def version(self) -> str:
        return self.get('app.version', '1.0.0')

    @property
    def theme(self) -> str:
        return self.get('app.theme', 'dark')

    @property
    def window_size(self) -> tuple:
        size = self.get('gui.window_size', [1400, 900])
        return tuple(size)

    @property
    def db_path(self) -> Path:
        if getattr(sys, 'frozen', False):
            base_path = Path(sys.executable).parent
        else:
            base_path = Path(__file__).parent.parent
        return base_path / self.get('database.path', 'data/websec.db')
