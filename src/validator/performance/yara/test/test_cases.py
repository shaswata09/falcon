#!/usr/bin/env python3
"""
YARA Rule Performance Evaluator - Test Cases

Comprehensive test cases covering various YARA rule patterns
and their expected performance scores.

Each test case includes:
- Input Rule
- Expected Score Range
- Expected Risk Level
- Expected Performance Recommendations
"""

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class TestCase:
    """Represents a single test case for the evaluator."""

    name: str
    description: str
    rule: str
    expected_score_range: Tuple[int, int]  # (min, max) inclusive
    expected_risk_level: str
    expected_issues: List[str]  # Key issues that should be detected


# =============================================================================
# TEST CASE DEFINITIONS
# =============================================================================

TEST_CASES = [
    # -------------------------------------------------------------------------
    # Test Case 1: Simple Signature - Fast Evaluation (Baseline)
    # -------------------------------------------------------------------------
    TestCase(
        name="TC01_Simple_Baseline",
        description="Simple rule with basic text strings - should be efficient",
        rule="""
rule simple_malware_sig {
    meta:
        description = "Simple malware detection"
        author = "Test"
    strings:
        $s1 = "malicious_payload" ascii
        $s2 = "evil_function" ascii
    condition:
        any of them
}
        """,
        expected_score_range=(0, 3),
        expected_risk_level="Fast and Efficient",
        expected_issues=[],
    ),
    # -------------------------------------------------------------------------
    # Test Case 2: Large Hex Blocks - Memory Heavy
    # -------------------------------------------------------------------------
    TestCase(
        name="TC02_Large_Hex_Blocks",
        description="Rule with large hex patterns - memory intensive",
        rule="""
rule large_hex_signature {
    meta:
        description = "Large hex pattern detection"
    strings:
        $hex1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
                  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                  00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00
                  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
                  69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
                  74 20 62 65 20 72 75 6E }
    condition:
        $hex1
}
        """,
        expected_score_range=(1, 4),
        expected_risk_level="Fast and Efficient",
        expected_issues=["Large Hex Pattern"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 3: Multiple Regex Expressions - High CPU
    # -------------------------------------------------------------------------
    TestCase(
        name="TC03_Multiple_Regex",
        description="Rule with multiple regex patterns - high CPU usage",
        rule="""
rule multi_regex_heavy {
    meta:
        description = "Multiple regex detection"
    strings:
        $r1 = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/
        $r2 = /[A-Za-z0-9+\/]{50,}={0,2}/
        $r3 = /(?:password|passwd|pwd)\s*[:=]\s*\S+/i
        $r4 = /\\x[0-9a-f]{2}/i
    condition:
        2 of them
}
        """,
        expected_score_range=(12, 25),
        expected_risk_level="High Performance Risk",
        expected_issues=["Multiple Regex Patterns", "Regex Pattern"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 4: Wildcard-Filled Hex Patterns - Scanning Slow
    # -------------------------------------------------------------------------
    TestCase(
        name="TC04_Wildcard_Heavy_Hex",
        description="Hex pattern with excessive wildcards - very slow scanning",
        rule="""
rule wildcard_heavy {
    meta:
        description = "Wildcard heavy hex"
    strings:
        $hex = { E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 85 C0 74 ?? 
                 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
                 50 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? }
    condition:
        $hex
}
        """,
        expected_score_range=(4, 8),
        expected_risk_level="Moderate - Can be Optimized",
        expected_issues=["Wildcard", "Heavy Wildcard"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 5: Redundant/Duplicate Strings - Optimization Expected
    # -------------------------------------------------------------------------
    TestCase(
        name="TC05_Redundant_Strings",
        description="Rule with overlapping/redundant string patterns",
        rule="""
rule redundant_strings {
    meta:
        description = "Overlapping strings"
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "CreateRemoteThreadEx" ascii
        $s3 = "Remote" ascii
        $s4 = "Thread" ascii
        $s5 = "CreateRemote" ascii
    condition:
        2 of them
}
        """,
        expected_score_range=(1, 4),
        expected_risk_level="Fast and Efficient",
        expected_issues=["Overlapping Strings"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 6: Expensive Modules - Heavy Runtime
    # -------------------------------------------------------------------------
    TestCase(
        name="TC06_Expensive_Modules",
        description="Rule using expensive PE, math, and hash modules",
        rule="""
import "pe"
import "math"
import "hash"

rule expensive_modules {
    meta:
        description = "Uses expensive modules"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and
        pe.number_of_sections > 3 and
        math.entropy(0, filesize) > 7.0 and
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}
        """,
        expected_score_range=(9, 18),
        expected_risk_level="High Performance Risk",
        expected_issues=["Expensive Module", "Expensive Condition Operation"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 7: Lean Optimized Rule - Expected Low Score
    # -------------------------------------------------------------------------
    TestCase(
        name="TC07_Optimized_Rule",
        description="Well-optimized rule with proper modifiers",
        rule="""
rule optimized_detection {
    meta:
        description = "Optimized detection rule"
    strings:
        $s1 = "cmd.exe" ascii fullword
        $s2 = "powershell" ascii nocase
        $h1 = { 4D 5A 90 00 }
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        any of them
}
        """,
        expected_score_range=(0, 3),
        expected_risk_level="Fast and Efficient",
        expected_issues=[],
    ),
    # -------------------------------------------------------------------------
    # Test Case 8: Very Complex Condition Logic - High Score Expected
    # -------------------------------------------------------------------------
    TestCase(
        name="TC08_Complex_Condition",
        description="Rule with deeply nested boolean logic",
        rule="""
rule complex_condition {
    meta:
        description = "Complex boolean condition"
    strings:
        $a1 = "string1" ascii
        $a2 = "string2" ascii
        $a3 = "string3" ascii
        $b1 = "other1" ascii
        $b2 = "other2" ascii
        $b3 = "other3" ascii
        $c1 = "more1" ascii
        $c2 = "more2" ascii
    condition:
        (($a1 and $a2) or ($a2 and $a3) or ($a1 and $a3)) and
        (($b1 and $b2) or ($b2 and $b3) or ($b1 and $b3)) and
        (($c1 or $c2) and ($a1 or $b1)) and
        ((#a1 > 2 and #a2 > 1) or (#b1 > 3 and #b2 > 2))
}
        """,
        expected_score_range=(4, 10),
        expected_risk_level="Moderate - Can be Optimized",
        expected_issues=["Complex Condition"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 9: Strings > 30 Entries - Flagged as Heavy
    # -------------------------------------------------------------------------
    TestCase(
        name="TC09_Many_Strings",
        description="Rule with excessive string count (>30)",
        rule="""
rule many_strings_rule {
    meta:
        description = "Too many strings"
    strings:
        $s01 = "string01" ascii $s02 = "string02" ascii $s03 = "string03" ascii
        $s04 = "string04" ascii $s05 = "string05" ascii $s06 = "string06" ascii
        $s07 = "string07" ascii $s08 = "string08" ascii $s09 = "string09" ascii
        $s10 = "string10" ascii $s11 = "string11" ascii $s12 = "string12" ascii
        $s13 = "string13" ascii $s14 = "string14" ascii $s15 = "string15" ascii
        $s16 = "string16" ascii $s17 = "string17" ascii $s18 = "string18" ascii
        $s19 = "string19" ascii $s20 = "string20" ascii $s21 = "string21" ascii
        $s22 = "string22" ascii $s23 = "string23" ascii $s24 = "string24" ascii
        $s25 = "string25" ascii $s26 = "string26" ascii $s27 = "string27" ascii
        $s28 = "string28" ascii $s29 = "string29" ascii $s30 = "string30" ascii
        $s31 = "string31" ascii $s32 = "string32" ascii $s33 = "string33" ascii
        $s34 = "string34" ascii $s35 = "string35" ascii
    condition:
        5 of them
}
        """,
        expected_score_range=(2, 5),
        expected_risk_level="Fast and Efficient",
        expected_issues=["Many Strings"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 10: Worst Case - Combines All Issues
    # -------------------------------------------------------------------------
    TestCase(
        name="TC10_Worst_Case",
        description="Deliberately combines all worst-case patterns",
        rule="""
import "pe"
import "cuckoo"
import "math"
import "hash"

rule worst_case_rule {
    meta:
        description = "Maximum complexity rule"
    strings:
        // Multiple regex with greedy patterns
        $r1 = /.*malware.*payload.*/i
        $r2 = /https?:\/\/.*\.exe/
        $r3 = /(cmd|powershell).*(-enc|-e).*[A-Za-z0-9+\/=]{20,}/
        
        // Wildcard-heavy hex
        $hex1 = { ?? ?? ?? ?? 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
                  ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
                  ?? ?? ?? ?? PE ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
        
        // Many text strings
        $s01 = "VirtualAlloc" $s02 = "VirtualProtect"
        $s03 = "WriteProcessMemory" $s04 = "CreateRemoteThread"
        $s05 = "NtUnmapViewOfSection" $s06 = "RtlMoveMemory"
        $s07 = "LoadLibraryA" $s08 = "GetProcAddress"
        $s09 = "OpenProcess" $s10 = "VirtualAllocEx"
        $s11 = "string11" $s12 = "string12" $s13 = "string13"
        $s14 = "string14" $s15 = "string15" $s16 = "string16"
        $s17 = "string17" $s18 = "string18" $s19 = "string19"
        $s20 = "string20" $s21 = "string21" $s22 = "string22"
        $s23 = "string23" $s24 = "string24" $s25 = "string25"
        $s26 = "string26" $s27 = "string27" $s28 = "string28"
        
        // Large string
        $large = "This is a very large string that is over one hundred characters long and will trigger the large string detection mechanism in the performance evaluator"
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        pe.number_of_sections > 2 and
        (
            (any of ($r*)) or
            ($hex1 and 3 of ($s*)) or
            (5 of ($s*) and $large)
        ) and
        math.entropy(0, filesize) > 6.5 and
        for any section in pe.sections : (
            section.characteristics & 0x20000000
        )
}
        """,
        expected_score_range=(50, 100),
        expected_risk_level="High Performance Risk",
        expected_issues=[
            "Multiple Regex",
            "Expensive Module",
            "Greedy Regex",
            "Many Strings",
            "Heavy Wildcard",
        ],
    ),
    # -------------------------------------------------------------------------
    # Test Case 11: Greedy Regex Only
    # -------------------------------------------------------------------------
    TestCase(
        name="TC11_Greedy_Regex",
        description="Single rule with greedy regex pattern",
        rule="""
rule greedy_regex_rule {
    strings:
        $r = /http.*\.exe.*download/i
    condition:
        $r
}
        """,
        expected_score_range=(4, 8),
        expected_risk_level="Moderate - Can be Optimized",
        expected_issues=["Greedy Regex", "Regex Pattern"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 12: Loop in Condition
    # -------------------------------------------------------------------------
    TestCase(
        name="TC12_Loop_Condition",
        description="Rule with for loop in condition",
        rule="""
import "pe"

rule loop_in_condition {
    strings:
        $s = "suspicious"
    condition:
        $s and
        for all i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size < 1000
        )
}
        """,
        expected_score_range=(5, 10),
        expected_risk_level="Moderate - Can be Optimized",
        expected_issues=["Loop in Condition", "Expensive Module"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 13: Missing Encoding Hints
    # -------------------------------------------------------------------------
    TestCase(
        name="TC13_Missing_Encoding",
        description="Strings without ascii/wide modifiers",
        rule="""
rule missing_encoding {
    strings:
        $s1 = "CreateProcess"
        $s2 = "ShellExecute"
        $s3 = "WinExec"
        $s4 = "cmd.exe"
    condition:
        2 of them
}
        """,
        expected_score_range=(3, 8),
        expected_risk_level="Moderate - Can be Optimized",
        expected_issues=["Missing Encoding Hint"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 14: Variable Jump Hex Pattern
    # -------------------------------------------------------------------------
    TestCase(
        name="TC14_Variable_Jump_Hex",
        description="Hex pattern with variable-length jumps",
        rule="""
rule variable_jump_hex {
    strings:
        $hex = { 55 8B EC [4-20] 8B 45 ?? [0-10] 50 E8 }
    condition:
        $hex
}
        """,
        expected_score_range=(2, 5),
        expected_risk_level="Fast and Efficient",
        expected_issues=["Variable Jump Pattern"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 15: ELF/Cuckoo Expensive Modules
    # -------------------------------------------------------------------------
    TestCase(
        name="TC15_Very_Expensive_Modules",
        description="Rule using very expensive cuckoo/elf modules",
        rule="""
import "elf"
import "cuckoo"

rule expensive_elf_cuckoo {
    strings:
        $s = ".rodata"
    condition:
        elf.type == elf.ET_EXEC and
        cuckoo.network.http_request(/.*malicious.*/)
}
        """,
        expected_score_range=(8, 15),
        expected_risk_level="High Performance Risk",
        expected_issues=["Expensive Module"],
    ),
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_all_test_cases() -> List[TestCase]:
    """Return all test cases."""
    return TEST_CASES


def get_test_case_by_name(name: str) -> TestCase:
    """Get a specific test case by name."""
    for tc in TEST_CASES:
        if tc.name == name:
            return tc
    raise ValueError(f"Test case '{name}' not found")


def print_test_cases():
    """Print all test cases in a formatted manner."""
    print("=" * 80)
    print("YARA RULE PERFORMANCE EVALUATOR - TEST CASES")
    print("=" * 80)

    for i, tc in enumerate(TEST_CASES, 1):
        print(f"\n{'─' * 80}")
        print(f"Test Case #{i}: {tc.name}")
        print(f"{'─' * 80}")
        print(f"Description: {tc.description}")
        print(f"\nInput Rule:")
        # Print first few lines of rule
        rule_lines = tc.rule.strip().split("\n")
        for line in rule_lines[:10]:
            print(f"  {line}")
        if len(rule_lines) > 10:
            print(f"  ... ({len(rule_lines) - 10} more lines)")
        print(
            f"\nExpected Score: {tc.expected_score_range[0]} - {tc.expected_score_range[1]}"
        )
        print(f"Expected Risk Level: {tc.expected_risk_level}")
        print(f"Expected Issues Detected:")
        if tc.expected_issues:
            for issue in tc.expected_issues:
                print(f"  • {issue}")
        else:
            print("  • None (efficient rule)")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    print_test_cases()
