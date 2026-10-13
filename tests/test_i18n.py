"""Tests for the i18n module."""

import re
from pathlib import Path

from pcap_report.i18n import LANGUAGES, TRANSLATIONS, Translator, get_translation


def test_all_keys_present_in_all_languages():
    en_keys = set(TRANSLATIONS["en"])
    for lang in LANGUAGES:
        keys = set(TRANSLATIONS[lang])
        assert keys == en_keys, f"{lang}: missing {en_keys - keys}, extra {keys - en_keys}"


def test_placeholders_match_between_languages():
    for key, text in TRANSLATIONS["en"].items():
        placeholders = set(re.findall(r"{(\w+)", text))
        assert placeholders == set(re.findall(r"{(\w+)", TRANSLATIONS["es"][key])), key


def test_get_translation():
    assert get_translation("en", "title") == "PCAP Analyzer"
    assert get_translation("es", "title") == "Analizador de PCAP"
    assert get_translation("fr", "title") == "PCAP Analyzer"
    assert get_translation("en", "nonexistent_key_xyz") == "[nonexistent_key_xyz]"


def test_translator_formats_and_switches():
    tr = Translator("en")
    assert "3.14" not in tr("loaded_packets")
    assert tr("loaded_packets", count=5) == "Loaded 5 packets."
    tr.set_language("es")
    assert tr("loaded_packets", count=5) == "Se cargaron 5 paquetes."
    tr.set_language("xx")  # unknown languages are ignored
    assert tr.lang == "es"


def test_translation_keys_used_in_code_exist():
    root = Path(__file__).resolve().parent.parent / "pcap_report"
    pattern = re.compile(r"""\btr_?\(\s*"([a-z0-9_]+)"|\bself\.t\(\s*'([a-z0-9_]+)'""")
    used = set()
    for path in root.rglob("*.py"):
        if path.name == "i18n.py":  # only docstring examples there
            continue
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            used.add(match.group(1) or match.group(2))
    assert used, "pattern should find translation calls"
    assert used <= set(TRANSLATIONS["en"]), used - set(TRANSLATIONS["en"])
