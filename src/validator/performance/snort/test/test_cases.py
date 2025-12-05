#!/usr/bin/env python3
"""
Snort Rule Performance Evaluator - Test Cases

This module contains comprehensive test cases covering various Snort rule
patterns and their expected performance scores.

Each test case includes:
- Input Rule
- Expected Score Range
- Expected Risk Level
- Expected Recommendations (key issues that should be detected)
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
    # Test Case 1: Simple Lightweight Rule (Content Only)
    # -------------------------------------------------------------------------
    TestCase(
        name="TC01_Simple_Content_Only",
        description="Simple rule with single content match - should be efficient",
        rule='alert tcp any any -> any 80 (msg:"Simple HTTP GET"; content:"GET"; depth:3; sid:1000001; rev:1;)',
        expected_score_range=(0, 3),
        expected_risk_level="Efficient",
        expected_issues=[],
    ),
    # -------------------------------------------------------------------------
    # Test Case 2: High Cost PCRE Rule (Greedy Regex)
    # -------------------------------------------------------------------------
    TestCase(
        name="TC02_Greedy_PCRE",
        description="Rule with greedy PCRE pattern - critical performance issue",
        rule='alert tcp any any -> any 80 (msg:"Greedy PCRE"; pcre:"/.*admin.*password.*/i"; sid:1000002; rev:1;)',
        expected_score_range=(8, 15),
        expected_risk_level="High Performance Risk",
        expected_issues=["PCRE Usage", "Greedy PCRE"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 3: Catastrophic Backtracking PCRE
    # -------------------------------------------------------------------------
    TestCase(
        name="TC03_Backtracking_PCRE",
        description="PCRE with nested quantifiers causing catastrophic backtracking",
        rule='alert tcp any any -> any 443 (msg:"Backtracking Regex"; pcre:"/((a+)+)+b/"; sid:1000003; rev:1;)',
        expected_score_range=(5, 12),
        expected_risk_level="Needs Optimization",
        expected_issues=["PCRE Usage", "Nested Groups"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 4: Missing fast_pattern
    # -------------------------------------------------------------------------
    TestCase(
        name="TC04_Missing_Fast_Pattern",
        description="Multiple long content strings without fast_pattern",
        rule='alert tcp any any -> any 80 (msg:"Missing fast_pattern"; content:"Authorization: Basic"; content:"username=administrator"; content:"password=secret123"; sid:1000004; rev:1;)',
        expected_score_range=(4, 8),
        expected_risk_level="Needs Optimization",
        expected_issues=["Missing fast_pattern", "Unanchored Multiple Content"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 5: Overlapping Content Patterns
    # -------------------------------------------------------------------------
    TestCase(
        name="TC05_Overlapping_Content",
        description="Content patterns that overlap/contain each other",
        rule='alert tcp any any -> any 80 (msg:"Overlapping Content"; content:"admin"; content:"administrator"; content:"admin_user"; sid:1000005; rev:1;)',
        expected_score_range=(4, 9),
        expected_risk_level="Needs Optimization",
        expected_issues=["Overlapping Content"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 6: Multi-Condition Boolean Chain
    # -------------------------------------------------------------------------
    TestCase(
        name="TC06_Boolean_Chain",
        description="Complex rule with multiple content and PCRE conditions",
        rule='alert tcp any any -> any 80 (msg:"Boolean Chain"; content:"POST"; content:"/login"; content:"user="; content:"pass="; pcre:"/[a-z]{4,}/"; sid:1000006; rev:1;)',
        expected_score_range=(5, 10),
        expected_risk_level="Needs Optimization",
        expected_issues=["Complex Boolean Chain", "PCRE Usage"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 7: Optimized Advanced Rule
    # -------------------------------------------------------------------------
    TestCase(
        name="TC07_Optimized_Rule",
        description="Well-optimized rule with proper anchoring and fast_pattern",
        rule='alert tcp any any -> any 80 (msg:"Optimized Rule"; content:"GET"; depth:4; content:"/api/v1/users"; fast_pattern; within:50; sid:1000007; rev:1;)',
        expected_score_range=(0, 3),
        expected_risk_level="Efficient",
        expected_issues=[],
    ),
    # -------------------------------------------------------------------------
    # Test Case 8: Very Poorly Optimized Rule (Kitchen Sink)
    # -------------------------------------------------------------------------
    TestCase(
        name="TC08_Worst_Case",
        description="Extremely poorly optimized rule with multiple issues",
        rule='alert tcp any any -> any any (msg:"Worst Case Rule"; content:"GET"; content:"POST"; content:"PUT"; content:"DELETE"; pcre:"/.*user.*pass.*/i"; pcre:"/.*admin.*/"; nocase; http_uri; http_header; http_cookie; http_method; sid:1000008; rev:1;)',
        expected_score_range=(15, 30),
        expected_risk_level="High Performance Risk",
        expected_issues=[
            "Multiple PCRE",
            "Greedy PCRE",
            "Complex Boolean Chain",
            "Excessive Transformations",
        ],
    ),
    # -------------------------------------------------------------------------
    # Test Case 9: Multiple byte_test Operations
    # -------------------------------------------------------------------------
    TestCase(
        name="TC09_Byte_Test_Loop",
        description="Rule with multiple relative byte_test operations",
        rule='alert tcp any any -> any 53 (msg:"DNS Amplification"; byte_test:2,>,512,0; byte_test:1,&,128,2,relative; byte_test:1,&,64,0,relative; sid:1000009; rev:1;)',
        expected_score_range=(2, 5),
        expected_risk_level="Efficient",
        expected_issues=["byte_test Loop Pattern"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 10: Negated Content Match
    # -------------------------------------------------------------------------
    TestCase(
        name="TC10_Negated_Content",
        description="Rule with negated content that requires full buffer scan",
        rule='alert tcp any any -> any 80 (msg:"Negated Content"; content:!"safe"; content:"malicious"; sid:1000010; rev:1;)',
        expected_score_range=(2, 5),
        expected_risk_level="Efficient",
        expected_issues=["Negated Content"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 11: PCRE with Lookahead
    # -------------------------------------------------------------------------
    TestCase(
        name="TC11_PCRE_Lookahead",
        description="PCRE using lookahead assertions",
        rule='alert tcp any any -> any 80 (msg:"Lookahead PCRE"; pcre:"/password(?=.*[0-9])/"; sid:1000011; rev:1;)',
        expected_score_range=(8, 14),
        expected_risk_level="High Performance Risk",
        expected_issues=["PCRE Usage", "Lookahead/Lookbehind", "Greedy PCRE"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 12: Complex Flowbits
    # -------------------------------------------------------------------------
    TestCase(
        name="TC12_Complex_Flowbits",
        description="Rule with multiple flowbits isset checks",
        rule='alert tcp any any -> any 80 (msg:"Complex Flowbits"; flowbits:isset,http.request; flowbits:isset,auth.attempt; content:"login"; sid:1000012; rev:1;)',
        expected_score_range=(1, 5),
        expected_risk_level="Efficient",
        expected_issues=["Complex Flowbits"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 13: HTTP Rule with Proper Buffers
    # -------------------------------------------------------------------------
    TestCase(
        name="TC13_HTTP_Buffered",
        description="HTTP rule using specific buffers - moderate complexity",
        rule='alert http any any -> any any (msg:"HTTP Buffer Rule"; http_uri; content:"/admin"; http_header; content:"X-Auth"; nocase; sid:1000013; rev:1;)',
        expected_score_range=(0, 4),
        expected_risk_level="Efficient",
        expected_issues=[],
    ),
    # -------------------------------------------------------------------------
    # Test Case 14: Multiple byte_extract Operations
    # -------------------------------------------------------------------------
    TestCase(
        name="TC14_Byte_Extract_Heavy",
        description="Rule with heavy byte_extract usage",
        rule='alert tcp any any -> any 445 (msg:"SMB Length Check"; byte_extract:4,0,len1,little; byte_extract:4,4,len2,little,relative; byte_extract:2,0,cmd,little,relative; byte_test:4,>,1000,0,relative; sid:1000014; rev:1;)',
        expected_score_range=(1, 5),
        expected_risk_level="Efficient",
        expected_issues=["Multiple byte_extract"],
    ),
    # -------------------------------------------------------------------------
    # Test Case 15: Minimal Rule - Baseline
    # -------------------------------------------------------------------------
    TestCase(
        name="TC15_Minimal_Baseline",
        description="Minimal viable Snort rule - baseline for scoring",
        rule='alert ip any any -> any any (msg:"IP Alert"; sid:1000015; rev:1;)',
        expected_score_range=(0, 0),
        expected_risk_level="Efficient",
        expected_issues=[],
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
    print("SNORT RULE PERFORMANCE EVALUATOR - TEST CASES")
    print("=" * 80)

    for i, tc in enumerate(TEST_CASES, 1):
        print(f"\n{'─' * 80}")
        print(f"Test Case #{i}: {tc.name}")
        print(f"{'─' * 80}")
        print(f"Description: {tc.description}")
        print(f"\nInput Rule:")
        print(f"  {tc.rule}")
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
