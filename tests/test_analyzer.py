"""Test suite for shellcode tester pro"""
from shellcode_tester.analyzer import ShellcodeAnalyzer

def test_null_byte_identification():
    analyzer = ShellcodeAnalyzer()
    sample = b"\x90\x90\x00\x31\xc0\x0a\x0f\x05"
    report = analyzer.analyze(sample)
    assert report.length == 8
    assert report.has_null_bytes is True
    assert "\\x00" in report.bad_characters_found
    assert "\\x0a" in report.bad_characters_found
    assert "x86_64:syscall" in report.detected_syscalls
    assert report.safe_for_staging is False

def test_clean_shellcode():
    analyzer = ShellcodeAnalyzer()
    sample = b"\x90\x90\x31\xc0\x48\x89\xc2"
    report = analyzer.analyze(sample)
    assert report.has_null_bytes is False
    assert len(report.bad_characters_found) == 0
    assert report.safe_for_staging is True
