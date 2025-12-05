#!/usr/bin/env python3
"""
YARA Rule Performance Evaluator - Test Runner

Executes all test cases against the evaluator and validates results.
Provides detailed output showing pass/fail status and actual vs expected values.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
from typing import List, Tuple

# Import the evaluator and test cases
from yara_performance_evaluator import YaraPerformanceEvaluator, EvaluationResult
from test_cases import TestCase, get_all_test_cases


class TestRunner:
    """Runs test cases and reports results."""

    def __init__(self):
        self.evaluator = YaraPerformanceEvaluator()
        self.passed = 0
        self.failed = 0
        self.results = []

    def run_all_tests(self, verbose: bool = True) -> Tuple[int, int]:
        """
        Run all test cases.

        Args:
            verbose: If True, print detailed output for each test

        Returns:
            Tuple of (passed_count, failed_count)
        """
        test_cases = get_all_test_cases()

        print("\n" + "=" * 80)
        print("YARA RULE PERFORMANCE EVALUATOR - TEST EXECUTION")
        print("=" * 80)
        print(f"\nRunning {len(test_cases)} test cases...\n")

        for tc in test_cases:
            result = self.run_single_test(tc, verbose)
            self.results.append(result)

        self._print_summary()
        return (self.passed, self.failed)

    def run_single_test(self, tc: TestCase, verbose: bool = True) -> dict:
        """
        Run a single test case.

        Args:
            tc: TestCase object
            verbose: If True, print detailed output

        Returns:
            Dictionary with test results
        """
        # Evaluate the rule
        eval_results = self.evaluator.evaluate_rule(tc.rule)

        # Handle case where no rules were parsed
        if not eval_results:
            if verbose:
                print(f"{'─' * 80}")
                print(f"\033[91m✗ FAIL\033[0m | {tc.name}")
                print(f"{'─' * 80}")
                print(f"  Error: No rules parsed from input")
                print()
            self.failed += 1
            return {"name": tc.name, "passed": False, "error": "No rules parsed"}

        # Get the first (or primary) result
        eval_result = eval_results[0]

        # Check if results match expectations
        score_pass = (
            tc.expected_score_range[0]
            <= eval_result.score
            <= tc.expected_score_range[1]
        )
        risk_pass = eval_result.risk_level == tc.expected_risk_level

        # Check if expected issues are detected
        detected_issues = set()
        for issue in eval_result.issues:
            for expected in tc.expected_issues:
                if expected.lower() in issue.lower():
                    detected_issues.add(expected)

        # At least 50% of expected issues should be detected (for non-empty expected)
        issues_pass = (
            len(detected_issues) >= len(tc.expected_issues) * 0.5
            if tc.expected_issues
            else True
        )

        # Overall pass/fail (score and risk level must match)
        test_passed = score_pass and risk_pass

        if test_passed:
            self.passed += 1
            status = "✓ PASS"
            status_color = "\033[92m"  # Green
        else:
            self.failed += 1
            status = "✗ FAIL"
            status_color = "\033[91m"  # Red

        reset_color = "\033[0m"

        if verbose:
            print(f"{'─' * 80}")
            print(f"{status_color}{status}{reset_color} | {tc.name}")
            print(f"{'─' * 80}")
            print(f"Rule: {eval_result.rule_name}")
            print()
            print(
                f"  Score:      {eval_result.score:3d}  (expected: {tc.expected_score_range[0]}-{tc.expected_score_range[1]}) {'✓' if score_pass else '✗'}"
            )
            print(
                f"  Risk Level: {eval_result.risk_level:30s} (expected: {tc.expected_risk_level}) {'✓' if risk_pass else '✗'}"
            )

            if tc.expected_issues:
                print(f"\n  Expected Issues Detection:")
                for issue in tc.expected_issues:
                    found = issue in detected_issues
                    print(f"    {'✓' if found else '○'} {issue}")

            if eval_result.issues:
                print(f"\n  Detected Issues ({len(eval_result.issues)}):")
                for issue in eval_result.issues[:6]:
                    print(f"    • {issue}")
                if len(eval_result.issues) > 6:
                    print(f"    ... and {len(eval_result.issues) - 6} more")

            if eval_result.suggestions:
                print(f"\n  Suggestions ({len(eval_result.suggestions)}):")
                for suggestion in eval_result.suggestions[:4]:
                    print(f"    → {suggestion}")
                if len(eval_result.suggestions) > 4:
                    print(f"    ... and {len(eval_result.suggestions) - 4} more")

            print()

        return {
            "name": tc.name,
            "passed": test_passed,
            "actual_score": eval_result.score,
            "expected_score_range": tc.expected_score_range,
            "actual_risk": eval_result.risk_level,
            "expected_risk": tc.expected_risk_level,
            "issues_detected": list(detected_issues),
            "expected_issues": tc.expected_issues,
            "all_issues": eval_result.issues,
            "suggestions": eval_result.suggestions,
        }

    def _print_summary(self):
        """Print test execution summary."""
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0

        print("\n" + "=" * 80)
        print("TEST EXECUTION SUMMARY")
        print("=" * 80)
        print(f"\n  Total Tests:  {total}")
        print(f"  Passed:       {self.passed} ({pass_rate:.1f}%)")
        print(f"  Failed:       {self.failed}")
        print()

        if self.failed > 0:
            print("  Failed Tests:")
            for result in self.results:
                if not result.get("passed", False):
                    print(f"    • {result['name']}")
                    if "actual_score" in result:
                        print(
                            f"      Score: {result['actual_score']} (expected {result['expected_score_range']})"
                        )
                        print(
                            f"      Risk: {result['actual_risk']} (expected {result['expected_risk']})"
                        )
                    elif "error" in result:
                        print(f"      Error: {result['error']}")
            print()

        if pass_rate >= 80:
            print("  \033[92m★ Test suite PASSED (≥80% pass rate)\033[0m")
        else:
            print("  \033[91m✗ Test suite FAILED (<80% pass rate)\033[0m")

        print("\n" + "=" * 80)


def run_example_evaluation():
    """Run example evaluation and display detailed JSON output."""
    print("\n" + "=" * 80)
    print("EXAMPLE EVALUATION OUTPUT")
    print("=" * 80)

    evaluator = YaraPerformanceEvaluator()

    # Example rules to demonstrate output format
    example_rules = """
// Example 1: Efficient rule
rule efficient_example {
    meta:
        description = "Well-optimized rule"
    strings:
        $mz = { 4D 5A }
        $s1 = "kernel32.dll" ascii nocase
    condition:
        $mz at 0 and $s1
}

// Example 2: Moderate complexity
rule moderate_example {
    strings:
        $r1 = /[a-z0-9]{32}/
        $s1 = "password"
        $s2 = "username"
    condition:
        any of them
}

// Example 3: High risk rule
import "pe"

rule high_risk_example {
    strings:
        $r1 = /.*malicious.*payload.*/i
        $r2 = /http.*exe/
        $hex = { ?? ?? 4D 5A ?? ?? ?? ?? }
    condition:
        pe.number_of_sections > 3 and any of them
}
    """

    print("\nJSON Output Examples:\n")

    results = evaluator.evaluate_rule(example_rules)
    for i, result in enumerate(results, 1):
        print(f"─── Rule #{i}: {result.rule_name} ───")
        print(result.to_json())
        print()

    # Generate full report
    print("─── Full Report (JSON) ───")
    report = evaluator.generate_report(results, "json")
    print(report)


def run_text_report_example():
    """Generate and display text format report."""
    print("\n" + "=" * 80)
    print("TEXT REPORT FORMAT EXAMPLE")
    print("=" * 80)

    evaluator = YaraPerformanceEvaluator()

    sample_rules = """
rule sample_rule_1 {
    strings:
        $s = "test" ascii
    condition:
        $s
}

rule sample_rule_2 {
    strings:
        $r = /test.*pattern/
    condition:
        $r
}

import "pe"
rule sample_rule_3 {
    strings:
        $s = "MZ"
    condition:
        $s and pe.number_of_sections > 0
}
    """

    results = evaluator.evaluate_rule(sample_rules)
    report = evaluator.generate_report(results, "text")
    print(report)


def demonstrate_api_usage():
    """Demonstrate various API usage patterns."""
    print("\n" + "=" * 80)
    print("API USAGE EXAMPLES")
    print("=" * 80)

    # Example 1: Quick evaluation
    print("\n─── Example 1: Quick Evaluation ───")
    from yara_performance_evaluator import evaluate

    results = evaluate(
        """
    rule quick_test {
        strings:
            $s = "malware"
        condition:
            $s
    }
    """
    )
    print(json.dumps(results, indent=2))

    # Example 2: Using the class directly
    print("\n─── Example 2: Class-based Evaluation ───")
    evaluator = YaraPerformanceEvaluator()
    results = evaluator.evaluate_rule(
        """
    import "pe"
    rule class_test {
        strings:
            $mz = { 4D 5A }
            $s = "suspicious" ascii
        condition:
            $mz at 0 and $s and pe.is_pe
    }
    """
    )

    for result in results:
        print(f"  Rule: {result.rule_name}")
        print(f"  Score: {result.score}")
        print(f"  Risk Level: {result.risk_level}")
        print(f"  Issues: {len(result.issues)}")

    # Example 3: Multiple rules in one file
    print("\n─── Example 3: Multiple Rules Evaluation ───")
    multi_rules = """
    rule rule_a { strings: $s = "a" condition: $s }
    rule rule_b { strings: $s = "b" $r = /test/ condition: any of them }
    rule rule_c { strings: $hex = { 00 11 22 ?? ?? 33 } condition: $hex }
    """

    results = evaluator.evaluate_rule(multi_rules)
    print(f"  Evaluated {len(results)} rules:")
    for r in results:
        print(f"    - {r.rule_name}: Score={r.score}, Risk={r.risk_level}")


def run_single_detailed_example():
    """Run a single detailed example showing full evaluation process."""
    print("\n" + "=" * 80)
    print("DETAILED SINGLE RULE EVALUATION")
    print("=" * 80)

    evaluator = YaraPerformanceEvaluator()

    complex_rule = """
import "pe"
import "math"

rule detect_backdoor_apt {
    meta:
        description = "Detects APT backdoor variant"
        author = "Security Researcher"
        severity = "high"
    
    strings:
        // C2 communication patterns
        $r1 = /https?:\/\/[a-z0-9\-\.]+\.(ru|cn|xyz)/i
        $r2 = /[A-Za-z0-9+\/]{100,}={0,2}/
        
        // Shellcode patterns
        $hex1 = { 55 8B EC ?? ?? ?? ?? 8B 45 ?? 50 }
        $hex2 = { E8 ?? ?? ?? ?? 83 C4 04 [2-8] C3 }
        
        // API calls
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
        
        // Config strings
        $cfg1 = "config.dat" wide
        $cfg2 = "settings.ini" wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        pe.number_of_sections >= 3 and
        (
            any of ($r*) or
            (1 of ($hex*) and 2 of ($api*)) or
            (all of ($cfg*) and math.entropy(0, 1024) > 7.0)
        )
}
    """

    print("\nInput Rule:")
    print("─" * 40)
    for line in complex_rule.strip().split("\n")[:25]:
        print(line)
    print("... (truncated)")

    print("\n" + "─" * 40)
    print("Evaluation Result:")
    print("─" * 40)

    results = evaluator.evaluate_rule(complex_rule)
    if results:
        result = results[0]
        print(f"\n{result.to_json()}")


if __name__ == "__main__":
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--examples":
            run_example_evaluation()
            run_text_report_example()
            demonstrate_api_usage()
            run_single_detailed_example()
        elif sys.argv[1] == "--quiet":
            runner = TestRunner()
            passed, failed = runner.run_all_tests(verbose=False)
            sys.exit(0 if failed == 0 else 1)
        elif sys.argv[1] == "--detailed":
            run_single_detailed_example()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python test_runner.py [--examples|--quiet|--detailed]")
            sys.exit(1)
    else:
        # Default: run all tests with verbose output
        runner = TestRunner()
        runner.run_all_tests(verbose=True)

        # Also show example outputs
        run_example_evaluation()
