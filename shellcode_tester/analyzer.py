"""
ScorpionXploit Shellcode Tester Pro - Analysis & Inspection Engine
Inspired by Joas Santos' Shellcode Tester Pro
Author: Aditya Sharma (scorpionxploit)
License: MIT
"""
from dataclasses import dataclass
from typing import List, Set, Dict

@dataclass
class ShellcodeAnalysisReport:
    length: int
    has_null_bytes: bool
    bad_characters_found: List[str]
    entropy: float
    detected_syscalls: List[str]
    safe_for_staging: bool

LINUX_X64_SYSCALLS: Dict[int, str] = {
    0: "sys_read",
    1: "sys_write",
    2: "sys_open",
    9: "sys_mmap",
    10: "sys_mprotect",
    59: "sys_execve",
    60: "sys_exit"
}

class ShellcodeAnalyzer:
    """Analyzes raw shellcode buffers safely without executing arbitrary machine code."""
    def __init__(self, restricted_chars: Optional[Set[int]] = None):
        self.restricted_chars = restricted_chars or {0x00, 0x0A, 0x0D}

    def analyze(self, raw_bytes: bytes) -> ShellcodeAnalysisReport:
        length = len(raw_bytes)
        bad_found = []
        for b in raw_bytes:
            if b in self.restricted_chars:
                bad_hex = f"\\x{b:02x}"
                if bad_hex not in bad_found:
                    bad_found.append(bad_hex)

        detected_syscalls = []
        for i in range(len(raw_bytes) - 2):
            # Look for 0x0f 0x05 (syscall instruction in x86_64)
            if raw_bytes[i] == 0x0F and raw_bytes[i+1] == 0x05:
                detected_syscalls.append("x86_64:syscall")

        return ShellcodeAnalysisReport(
            length=length,
            has_null_bytes=0x00 in raw_bytes,
            bad_characters_found=bad_found,
            entropy=round(len(set(raw_bytes)) / 256.0, 3),
            detected_syscalls=detected_syscalls,
            safe_for_staging=len(bad_found) == 0
        )
