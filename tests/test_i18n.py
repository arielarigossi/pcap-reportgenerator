"""Tests for the i18n module."""

from pcap_report.i18n import TRANSLATIONS, get_translation


def test_all_keys_present_in_both_languages():
    en_keys = set(TRANSLATIONS["en"].keys())
    es_keys = set(TRANSLATIONS["es"].keys())
    assert en_keys == es_keys, f"Missing in es: {en_keys - es_keys}, extra in es: {es_keys - en_keys}"


def test_get_translation_english():
    assert get_translation("en", "title") == "PCAP Analyzer Report"


def test_get_translation_spanish():
    assert get_translation("es", "title") == "Reporte del Analizador de PCAP"


def test_get_translation_unknown_lang_falls_back_to_english():
    assert get_translation("fr", "title") == "PCAP Analyzer Report"


def test_get_translation_unknown_key():
    result = get_translation("en", "nonexistent_key_xyz")
    assert result == "[nonexistent_key_xyz]"


def test_format_string_support():
    result = get_translation("en", "analysis_completed").format(time=3.14)
    assert "3.14" in result
