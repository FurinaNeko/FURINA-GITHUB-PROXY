"""轻量多语言支持：语言表放在 assets/i18n.json，默认英语，缺键回退英语。

设计原则：
  * 不认识的语言码就退回 en，绝不抛异常（UI 不能因为少一句翻译就崩）；
  * 文本里的 {version}/{qq} 之类占位符用 str.format 填充，填错了也只会返回原文。
"""

from __future__ import annotations

import json
from pathlib import Path

from .icon import resource_path

DEFAULT_LANG = "en"

_CATALOG: dict | None = None


def load_catalog() -> dict:
    global _CATALOG
    if _CATALOG is not None:
        return _CATALOG
    data: dict = {"languages": [{"code": "en", "label": "English"}],
                  "app": {"en": {}}, "installer": {"en": {}}}
    try:
        path = resource_path("assets/i18n.json")
        if Path(path).exists():
            loaded = json.loads(Path(path).read_text(encoding="utf-8"))
            data.update(loaded)
    except Exception:  # noqa: BLE001
        pass
    _CATALOG = data
    return data


def languages() -> list[dict]:
    """[{'code': 'en', 'label': 'English'}, ...]，顺序即下拉框顺序。"""
    return list(load_catalog().get("languages") or [{"code": "en", "label": "English"}])


def language_label(code: str) -> str:
    for item in languages():
        if item.get("code") == code:
            return str(item.get("label", code))
    return code


class Translator:
    def __init__(self, kind: str = "app", lang: str = DEFAULT_LANG):
        self.kind = kind
        self.lang = DEFAULT_LANG
        self._table: dict = {}
        self._fallback: dict = {}
        self.set_language(lang)

    def set_language(self, lang: str) -> None:
        catalog = load_catalog()
        section = catalog.get(self.kind) or {}
        available = set(section)
        self.lang = lang if lang in available else DEFAULT_LANG
        self._table = section.get(self.lang) or {}
        self._fallback = section.get(DEFAULT_LANG) or {}

    def __call__(self, key: str, **kwargs) -> str:
        text = self._table.get(key)
        if text is None:
            text = self._fallback.get(key, key)
        if kwargs:
            try:
                return text.format(**kwargs)
            except (KeyError, IndexError, ValueError):
                return text
        return text
