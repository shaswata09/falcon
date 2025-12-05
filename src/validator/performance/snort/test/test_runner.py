#!/usr/bin/env python3
"""
Snort Rule Performance Evaluator - Test Runner

Executes all test cases against the evaluator and validates results.
Provides detailed output showing pass/fail status and actual vs expected values.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
from typing import List, Tuple

# Import the evaluator and test cases
from snort_performance_evaluator import SnortPerformanceEvaluator, EvaluationResult
from snort_performance_evaluator import evaluate
from test_cases import TestCase, get_all_test_cases


class TestRunner:
    """Runs test cases and reports results."""

    def __init__(self):
        self.evaluator = SnortPerformanceEvaluator()
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
        print("SNORT RULE PERFORMANCE EVALUATOR - TEST EXECUTION")
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
        eval_result = self.evaluator.evaluate_rule(tc.rule)

        # Check if results match expectations
        score_pass = (
            tc.expected_score_range[0]
            <= eval_result.score
            <= tc.expected_score_range[1]
        )
        risk_pass = eval_result.risk_level == tc.expected_risk_level

        # Check if expected issues are detected
        detected_issues = set()
        for reason in eval_result.reasons:
            for expected in tc.expected_issues:
                if expected.lower() in reason.lower():
                    detected_issues.add(expected)

        issues_pass = (
            len(detected_issues) >= len(tc.expected_issues) * 0.5
        )  # At least 50% of issues detected

        # Overall pass/fail
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
            print(
                f"Rule: {tc.rule[:70]}..." if len(tc.rule) > 70 else f"Rule: {tc.rule}"
            )
            print()
            print(
                f"  Score:      {eval_result.score:3d}  (expected: {tc.expected_score_range[0]}-{tc.expected_score_range[1]}) {'✓' if score_pass else '✗'}"
            )
            print(
                f"  Risk Level: {eval_result.risk_level:25s} (expected: {tc.expected_risk_level}) {'✓' if risk_pass else '✗'}"
            )

            if tc.expected_issues:
                print(f"\n  Expected Issues Detection:")
                for issue in tc.expected_issues:
                    found = issue in detected_issues
                    print(f"    {'✓' if found else '✗'} {issue}")

            if eval_result.reasons:
                print(f"\n  Detected Issues:")
                for reason in eval_result.reasons[:5]:  # Limit to first 5
                    print(f"    • {reason}")
                if len(eval_result.reasons) > 5:
                    print(f"    ... and {len(eval_result.reasons) - 5} more")

            if eval_result.suggestions:
                print(f"\n  Suggestions:")
                for suggestion in eval_result.suggestions[:3]:  # Limit to first 3
                    print(f"    → {suggestion}")
                if len(eval_result.suggestions) > 3:
                    print(f"    ... and {len(eval_result.suggestions) - 3} more")

            print()

        return {
            "name": tc.name,
            "passed": test_passed,
            "actual_score": eval_result.score,
            "expected_score_range": tc.expected_score_range,
            "actual_risk": eval_result.risk_level,
            "expected_risk": tc.expected_risk_level,
            "issues_detected": list(detected_issues),
            "all_reasons": eval_result.reasons,
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
                if not result["passed"]:
                    print(f"    • {result['name']}")
                    print(
                        f"      Score: {result['actual_score']} (expected {result['expected_score_range']})"
                    )
                    print(
                        f"      Risk: {result['actual_risk']} (expected {result['expected_risk']})"
                    )
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

    evaluator = SnortPerformanceEvaluator()

    # Example rules to demonstrate output format
    example_rules = [
        # Efficient rule
        'alert tcp any any -> any 80 (msg:"Simple GET"; content:"GET"; depth:4; sid:100001;)',
        # High risk rule
        'alert tcp any any -> any 80 (msg:"Complex Rule"; pcre:"/.*admin.*pass.*/i"; content:"login"; content:"user"; sid:100002;)',
        # Medium risk rule
        'alert tcp any any -> any 443 (msg:"SSL Check"; content:"TLS"; content:"certificate"; content:"verify"; sid:100003;)',
    ]

    print("\nJSON Output Examples:\n")

    for i, rule in enumerate(example_rules, 1):
        print(f"─── Rule #{i} ───")
        result = evaluator.evaluate_rule(rule)
        print(result.to_json())
        print()

    # Generate full report
    print("─── Full Report (Multiple Rules) ───")
    results = evaluator.evaluate_rules(example_rules)
    report = evaluator.generate_report(results, "json")
    print(report)


def run_text_report_example():
    """Generate and display text format report."""
    print("\n" + "=" * 80)
    print("TEXT REPORT FORMAT EXAMPLE")
    print("=" * 80)

    evaluator = SnortPerformanceEvaluator()

    sample_rules = [
        'alert tcp any any -> any 80 (msg:"GET Request"; content:"GET"; depth:4; fast_pattern; sid:1;)',
        'alert tcp any any -> any 80 (msg:"PCRE Heavy"; pcre:"/.*test.*/"; pcre:"/.*data.*/"; sid:2;)',
        'alert tcp any any -> any 80 (msg:"Overlapping"; content:"admin"; content:"administrator"; sid:3;)',
    ]

    results = evaluator.evaluate_rules(sample_rules)
    report = evaluator.generate_report(results, "text")
    print(report)


def demonstrate_api_usage():
    """Demonstrate various API usage patterns."""
    print("\n" + "=" * 80)
    print("API USAGE EXAMPLES")
    print("=" * 80)

    # Example 1: Quick single rule evaluation
    print("\n─── Example 1: Quick Evaluation ───")

    result = evaluate(
        'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; pcre:"/.*admin.*/"; sid:1;)'
    )
    print(json.dumps(result, indent=2))

    # Example 2: Using the class directly
    print("\n─── Example 2: Class-based Evaluation ───")
    evaluator = SnortPerformanceEvaluator()
    result = evaluator.evaluate_rule(
        'alert tcp any any -> any 443 (msg:"SSL Attack"; content:"|16 03|"; depth:2; '
        'content:"|01|"; distance:3; within:1; sid:2;)'
    )
    print(f"Score: {result.score}")
    print(f"Risk Level: {result.risk_level}")
    print(f"Issues: {len(result.reasons)}")

    # Example 3: Batch evaluation
    print("\n─── Example 3: Batch Evaluation ───")
    rules = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; content:"A"; sid:1;)',
        'alert tcp any any -> any 80 (msg:"Rule 2"; content:"B"; pcre:"/.*/"; sid:2;)',
        'alert tcp any any -> any 80 (msg:"Rule 3"; content:"C"; depth:1; sid:3;)',
    ]

    results = evaluator.evaluate_rules(rules)
    for i, r in enumerate(results, 1):
        print(f"  Rule {i}: Score={r.score}, Risk={r.risk_level}")


if __name__ == "__main__":
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--examples":
            run_example_evaluation()
            run_text_report_example()
            demonstrate_api_usage()
        elif sys.argv[1] == "--quiet":
            runner = TestRunner()
            passed, failed = runner.run_all_tests(verbose=False)
            sys.exit(0 if failed == 0 else 1)
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python test_runner.py [--examples|--quiet]")
            sys.exit(1)
    else:
        # Default: run all tests with verbose output
        runner = TestRunner()
        runner.run_all_tests(verbose=True)

        # Also show example outputs
        run_example_evaluation()
