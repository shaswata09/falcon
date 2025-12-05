#!/usr/bin/env python3
"""
Snort Rule Performance Evaluator

Analyzes Snort IDS/IPS signatures and predicts potential runtime performance overhead.
Statically assesses rule complexity and determines whether a rule is likely to degrade
throughput or increase packet processing latency.

Author: Claude AI
Version: 1.0.0
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class RiskLevel(Enum):
    """Risk level classification for Snort rules."""

    EFFICIENT = "Efficient"
    NEEDS_OPTIMIZATION = "Needs Optimization"
    HIGH_RISK = "High Performance Risk"


@dataclass
class PerformanceIssue:
    """Represents a detected performance issue in a Snort rule."""

    name: str
    cost: int
    description: str
    suggestion: str


@dataclass
class EvaluationResult:
    """Complete evaluation result for a Snort rule."""

    score: int
    risk_level: str
    reasons: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "suggestions": self.suggestions,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class SnortRuleParser:
    """
    Parser for Snort rule syntax.
    Extracts rule components for performance analysis.
    """

    # Regex patterns for parsing Snort rules
    RULE_HEADER_PATTERN = re.compile(
        r"^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+"
        r"(\w+)\s+"  # protocol
        r"(\S+)\s+"  # src_ip
        r"(\S+)\s+"  # src_port
        r"(->|<>)\s+"  # direction
        r"(\S+)\s+"  # dst_ip
        r"(\S+)\s*"  # dst_port
        r"\((.*)\)\s*$",  # options
        re.DOTALL | re.IGNORECASE,
    )

    # Pattern to match option:value pairs in rule body
    OPTION_PATTERN = re.compile(
        r"(\w+)\s*:\s*([^;]*?)(?=\s*;\s*\w+\s*:|;\s*\)|\s*;\s*$)|(\w+)\s*;", re.DOTALL
    )

    def __init__(self):
        self.parsed_rules = []

    def parse_rule(self, rule_text: str) -> Optional[dict]:
        """
        Parse a single Snort rule and extract its components.

        Args:
            rule_text: Raw Snort rule string

        Returns:
            Dictionary containing parsed rule components or None if parsing fails
        """
        # Clean up the rule text
        rule_text = rule_text.strip()

        # Skip comments and empty lines
        if not rule_text or rule_text.startswith("#"):
            return None

        # Match the rule header
        match = self.RULE_HEADER_PATTERN.match(rule_text)
        if not match:
            # Try a more lenient parse for malformed rules
            return self._lenient_parse(rule_text)

        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_str = (
            match.groups()
        )

        # Parse options
        options = self._parse_options(options_str)

        return {
            "raw": rule_text,
            "action": action,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "direction": direction,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "options": options,
            "options_str": options_str,
        }

    def _lenient_parse(self, rule_text: str) -> Optional[dict]:
        """Lenient parsing for rules that don't match standard format."""
        # Try to extract just the options portion
        options_match = re.search(r"\((.+)\)\s*$", rule_text, re.DOTALL)
        if options_match:
            options_str = options_match.group(1)
            options = self._parse_options(options_str)
            return {
                "raw": rule_text,
                "action": "unknown",
                "protocol": "unknown",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "any",
                "options": options,
                "options_str": options_str,
            }
        return None

    def _parse_options(self, options_str: str) -> dict:
        """
        Parse the options portion of a Snort rule.

        Args:
            options_str: The options string from within the parentheses

        Returns:
            Dictionary mapping option names to their values (list for repeated options)
        """
        options = {}

        # Split by semicolon and parse each option
        # Handle quoted strings and escaped characters
        current_option = ""
        in_quotes = False
        escape_next = False

        for char in options_str:
            if escape_next:
                current_option += char
                escape_next = False
            elif char == "\\":
                current_option += char
                escape_next = True
            elif char == '"':
                current_option += char
                in_quotes = not in_quotes
            elif char == ";" and not in_quotes:
                self._add_option(options, current_option.strip())
                current_option = ""
            else:
                current_option += char

        # Handle last option
        if current_option.strip():
            self._add_option(options, current_option.strip())

        return options

    def _add_option(self, options: dict, option_str: str):
        """Add a single option to the options dictionary."""
        if not option_str:
            return

        # Handle options with values (key:value)
        if ":" in option_str:
            key, _, value = option_str.partition(":")
            key = key.strip().lower()
            value = value.strip()
        else:
            # Options without values (flags)
            key = option_str.strip().lower()
            value = True

        # Handle multiple instances of same option
        if key in options:
            if isinstance(options[key], list):
                options[key].append(value)
            else:
                options[key] = [options[key], value]
        else:
            options[key] = value

    def parse_file(self, filepath: str) -> list:
        """
        Parse all rules from a .rules file.

        Args:
            filepath: Path to the .rules file

        Returns:
            List of parsed rule dictionaries
        """
        parsed = []
        with open(filepath, "r") as f:
            for line in f:
                result = self.parse_rule(line)
                if result:
                    parsed.append(result)
        return parsed


class PerformanceAnalyzer:
    """
    Analyzes parsed Snort rules for performance issues.

    Scoring System:
    - 0-3: Efficient
    - 4-7: Needs Optimization
    - 8+: High Performance Risk
    """

    # Performance cost constants
    COST_PCRE_BASIC = 3
    COST_PCRE_GREEDY = 5
    COST_PCRE_BACKTRACK = 6
    COST_PCRE_NESTED_GROUPS = 2
    COST_PCRE_LOOKAHEAD = 3
    COST_CONTENT_NO_DEPTH = 2
    COST_OVERLAPPING_CONTENT = 3
    COST_NO_FAST_PATTERN = 2
    COST_MULTIPLE_OR = 2
    COST_BYTE_EXTRACT = 2
    COST_BYTE_TEST_LOOP = 3
    COST_EXCESSIVE_TRANSFORMS = 2
    COST_NEGATED_CONTENT = 1
    COST_MULTIPLE_PCRE = 4
    COST_FLOWBITS_COMPLEX = 1

    # Greedy/backtracking patterns in PCRE
    GREEDY_PATTERNS = [
        r"\.\*",  # .* greedy wildcard
        r"\.\+",  # .+ greedy one-or-more
        r"\.\{[0-9,]+\}",  # .{n,m} quantified dot
        r"\(\.\*\)",  # captured greedy
        r"\[\^[^\]]*\]\*",  # negated character class with *
        r"\[\^[^\]]*\]\+",  # negated character class with +
    ]

    BACKTRACK_PATTERNS = [
        r"\(\.\*\)\{",  # grouped wildcard with quantifier
        r"\(\.\+\)\{",  # grouped one-or-more with quantifier
        r"\(\?\:.*\)\*",  # non-capturing group with *
        r"\(\?\:.*\)\+",  # non-capturing group with +
        r"\w+\*.*\w+\*",  # multiple wildcards
    ]

    LOOKAHEAD_PATTERNS = [
        r"\(\?=",  # positive lookahead
        r"\(\?!",  # negative lookahead
        r"\(\?<=",  # positive lookbehind
        r"\(\?<!",  # negative lookbehind
    ]

    def __init__(self):
        self.issues = []

    def analyze(self, parsed_rule: dict) -> EvaluationResult:
        """
        Analyze a parsed Snort rule for performance issues.

        Args:
            parsed_rule: Dictionary from SnortRuleParser

        Returns:
            EvaluationResult with score, risk level, and recommendations
        """
        self.issues = []
        score = 0
        options = parsed_rule.get("options", {})

        # Check PCRE patterns
        score += self._analyze_pcre(options)

        # Check content matches
        score += self._analyze_content(options)

        # Check for fast_pattern usage
        score += self._analyze_fast_pattern(options)

        # Check for byte_extract/byte_test patterns
        score += self._analyze_byte_operations(options)

        # Check for complex boolean conditions
        score += self._analyze_boolean_complexity(options)

        # Check for transformation modifiers
        score += self._analyze_transformations(options)

        # Check for flowbits complexity
        score += self._analyze_flowbits(options)

        # Determine risk level
        risk_level = self._get_risk_level(score)

        return EvaluationResult(
            score=score,
            risk_level=risk_level.value,
            reasons=[issue.description for issue in self.issues],
            suggestions=[issue.suggestion for issue in self.issues],
            details={
                "issue_breakdown": [
                    {"name": i.name, "cost": i.cost} for i in self.issues
                ]
            },
        )

    def _analyze_pcre(self, options: dict) -> int:
        """Analyze PCRE patterns for performance issues."""
        score = 0
        pcre_values = options.get("pcre", [])

        if not pcre_values:
            return 0

        # Normalize to list
        if not isinstance(pcre_values, list):
            pcre_values = [pcre_values]

        # Multiple PCRE patterns are expensive
        if len(pcre_values) > 1:
            self.issues.append(
                PerformanceIssue(
                    name="Multiple PCRE",
                    cost=self.COST_MULTIPLE_PCRE,
                    description=f"Multiple PCRE patterns ({len(pcre_values)}) increase processing time",
                    suggestion="Consolidate PCRE patterns or replace with content matches where possible",
                )
            )
            score += self.COST_MULTIPLE_PCRE

        for pcre in pcre_values:
            pcre_str = str(pcre)

            # Basic PCRE usage cost
            score += self.COST_PCRE_BASIC
            self.issues.append(
                PerformanceIssue(
                    name="PCRE Usage",
                    cost=self.COST_PCRE_BASIC,
                    description="PCRE regex usage has inherent performance cost",
                    suggestion="Consider replacing PCRE with 'content' + 'within'/'distance' if possible",
                )
            )

            # Check for greedy patterns
            for pattern in self.GREEDY_PATTERNS:
                if re.search(pattern, pcre_str):
                    self.issues.append(
                        PerformanceIssue(
                            name="Greedy PCRE",
                            cost=self.COST_PCRE_GREEDY,
                            description="Greedy wildcard pattern (.*/.+) causes excessive backtracking",
                            suggestion="Use non-greedy quantifiers (.*?/.+?) or limit with {n,m}",
                        )
                    )
                    score += self.COST_PCRE_GREEDY
                    break

            # Check for backtracking patterns
            for pattern in self.BACKTRACK_PATTERNS:
                if re.search(pattern, pcre_str):
                    self.issues.append(
                        PerformanceIssue(
                            name="Backtracking PCRE",
                            cost=self.COST_PCRE_BACKTRACK,
                            description="Pattern likely to cause catastrophic backtracking",
                            suggestion="Restructure regex to avoid nested quantifiers",
                        )
                    )
                    score += self.COST_PCRE_BACKTRACK
                    break

            # Check for lookahead/lookbehind
            for pattern in self.LOOKAHEAD_PATTERNS:
                if re.search(pattern, pcre_str):
                    self.issues.append(
                        PerformanceIssue(
                            name="Lookahead/Lookbehind",
                            cost=self.COST_PCRE_LOOKAHEAD,
                            description="Lookahead/lookbehind assertions add complexity",
                            suggestion="Consider restructuring without lookahead if possible",
                        )
                    )
                    score += self.COST_PCRE_LOOKAHEAD
                    break

            # Check for nested capturing groups
            nested_groups = len(re.findall(r"\([^)]*\([^)]*\)", pcre_str))
            if nested_groups > 0:
                self.issues.append(
                    PerformanceIssue(
                        name="Nested Groups",
                        cost=self.COST_PCRE_NESTED_GROUPS,
                        description=f"Nested capturing groups ({nested_groups}) increase memory usage",
                        suggestion="Use non-capturing groups (?:...) where captures aren't needed",
                    )
                )
                score += self.COST_PCRE_NESTED_GROUPS

        return score

    def _analyze_content(self, options: dict) -> int:
        """Analyze content match patterns for performance issues."""
        score = 0
        content_values = options.get("content", [])

        if not content_values:
            return 0

        # Normalize to list
        if not isinstance(content_values, list):
            content_values = [content_values]

        has_depth = "depth" in options
        has_offset = "offset" in options
        has_within = "within" in options
        has_distance = "distance" in options

        # Check each content match
        content_strings = []
        for content in content_values:
            content_str = str(content).strip("\"'")
            content_strings.append(content_str)

            # Check for negated content (starts with !)
            if content_str.startswith("!"):
                self.issues.append(
                    PerformanceIssue(
                        name="Negated Content",
                        cost=self.COST_NEGATED_CONTENT,
                        description="Negated content match requires scanning entire buffer",
                        suggestion="Place positive content matches before negated ones",
                    )
                )
                score += self.COST_NEGATED_CONTENT

        # Multiple content without anchoring
        if len(content_values) > 1 and not (
            has_depth or has_offset or has_within or has_distance
        ):
            self.issues.append(
                PerformanceIssue(
                    name="Unanchored Multiple Content",
                    cost=self.COST_CONTENT_NO_DEPTH,
                    description="Multiple content matches without depth/offset/within constraints",
                    suggestion="Add 'depth', 'offset', 'within', or 'distance' to anchor content searches",
                )
            )
            score += self.COST_CONTENT_NO_DEPTH

        # Check for overlapping content patterns
        overlaps = self._check_content_overlap(content_strings)
        if overlaps:
            self.issues.append(
                PerformanceIssue(
                    name="Overlapping Content",
                    cost=self.COST_OVERLAPPING_CONTENT,
                    description=f"Overlapping content patterns detected: {overlaps}",
                    suggestion="Remove redundant content matches or consolidate patterns",
                )
            )
            score += self.COST_OVERLAPPING_CONTENT

        return score

    def _check_content_overlap(self, content_strings: list) -> list:
        """Check for overlapping content patterns."""
        overlaps = []
        for i, s1 in enumerate(content_strings):
            for j, s2 in enumerate(content_strings):
                if i < j:
                    # Remove quotes and hex notation for comparison
                    clean_s1 = re.sub(r"\|[0-9A-Fa-f ]+\|", "", s1)
                    clean_s2 = re.sub(r"\|[0-9A-Fa-f ]+\|", "", s2)

                    if clean_s1 in clean_s2 or clean_s2 in clean_s1:
                        overlaps.append(f"'{s1}' and '{s2}'")
        return overlaps

    def _analyze_fast_pattern(self, options: dict) -> int:
        """Check for fast_pattern usage on long content strings."""
        score = 0
        content_values = options.get("content", [])
        has_fast_pattern = "fast_pattern" in options

        if not content_values:
            return 0

        # Normalize to list
        if not isinstance(content_values, list):
            content_values = [content_values]

        # Check if any content is long enough to benefit from fast_pattern
        long_content_count = 0
        for content in content_values:
            content_str = str(content).strip("\"'")
            # Remove hex notation for length calculation
            clean_content = re.sub(r"\|[0-9A-Fa-f ]+\|", "", content_str)
            if len(clean_content) >= 8:
                long_content_count += 1

        # If there are multiple long content strings without fast_pattern
        if long_content_count > 1 and not has_fast_pattern:
            self.issues.append(
                PerformanceIssue(
                    name="Missing fast_pattern",
                    cost=self.COST_NO_FAST_PATTERN,
                    description="Long content strings without fast_pattern designation",
                    suggestion="Add 'fast_pattern' to the most unique/selective content match",
                )
            )
            score += self.COST_NO_FAST_PATTERN

        return score

    def _analyze_byte_operations(self, options: dict) -> int:
        """Analyze byte_extract and byte_test operations."""
        score = 0

        # Check byte_extract
        if "byte_extract" in options:
            byte_extracts = options["byte_extract"]
            if not isinstance(byte_extracts, list):
                byte_extracts = [byte_extracts]

            if len(byte_extracts) > 2:
                self.issues.append(
                    PerformanceIssue(
                        name="Multiple byte_extract",
                        cost=self.COST_BYTE_EXTRACT,
                        description=f"Multiple byte_extract operations ({len(byte_extracts)})",
                        suggestion="Minimize byte_extract usage or combine operations",
                    )
                )
                score += self.COST_BYTE_EXTRACT

        # Check byte_test
        if "byte_test" in options:
            byte_tests = options["byte_test"]
            if not isinstance(byte_tests, list):
                byte_tests = [byte_tests]

            # Check for potential loops (multiple byte_test with relative)
            relative_count = sum(
                1 for bt in byte_tests if "relative" in str(bt).lower()
            )
            if relative_count > 1:
                self.issues.append(
                    PerformanceIssue(
                        name="byte_test Loop Pattern",
                        cost=self.COST_BYTE_TEST_LOOP,
                        description="Multiple relative byte_test operations may create loop-like behavior",
                        suggestion="Consider combining byte tests or using PCRE for complex patterns",
                    )
                )
                score += self.COST_BYTE_TEST_LOOP

        return score

    def _analyze_boolean_complexity(self, options: dict) -> int:
        """Analyze boolean logic complexity in rule options."""
        score = 0
        options_str = str(options)

        # Check for OR chaining in content (multiple content without 'and')
        content_values = options.get("content", [])
        pcre_values = options.get("pcre", [])

        # Normalize to lists
        if not isinstance(content_values, list):
            content_values = [content_values] if content_values else []
        if not isinstance(pcre_values, list):
            pcre_values = [pcre_values] if pcre_values else []

        # Multiple detection methods without clear chaining
        total_matches = len(content_values) + len(pcre_values)
        if total_matches > 3:
            self.issues.append(
                PerformanceIssue(
                    name="Complex Boolean Chain",
                    cost=self.COST_MULTIPLE_OR,
                    description=f"Complex rule with {total_matches} match conditions",
                    suggestion="Split into multiple rules or use detection_filter to reduce false positives",
                )
            )
            score += self.COST_MULTIPLE_OR

        return score

    def _analyze_transformations(self, options: dict) -> int:
        """Analyze transformation modifiers."""
        score = 0
        transform_count = 0

        # List of transformation keywords
        transforms = [
            "nocase",
            "rawbytes",
            "http_uri",
            "http_header",
            "http_cookie",
            "http_client_body",
            "http_method",
            "http_stat_code",
            "http_stat_msg",
            "normalize",
        ]

        for transform in transforms:
            if transform in options:
                transform_count += 1

        if transform_count > 3:
            self.issues.append(
                PerformanceIssue(
                    name="Excessive Transformations",
                    cost=self.COST_EXCESSIVE_TRANSFORMS,
                    description=f"Multiple transformation modifiers ({transform_count}) applied",
                    suggestion="Reduce transformation modifiers or target specific buffer",
                )
            )
            score += self.COST_EXCESSIVE_TRANSFORMS

        return score

    def _analyze_flowbits(self, options: dict) -> int:
        """Analyze flowbits complexity."""
        score = 0

        if "flowbits" in options:
            flowbits = options["flowbits"]
            if not isinstance(flowbits, list):
                flowbits = [flowbits]

            # Complex flowbits operations
            isset_count = sum(1 for fb in flowbits if "isset" in str(fb).lower())
            if isset_count > 1:
                self.issues.append(
                    PerformanceIssue(
                        name="Complex Flowbits",
                        cost=self.COST_FLOWBITS_COMPLEX,
                        description="Multiple flowbits isset checks",
                        suggestion="Simplify flowbits logic or use state machine approach",
                    )
                )
                score += self.COST_FLOWBITS_COMPLEX

        return score

    def _get_risk_level(self, score: int) -> RiskLevel:
        """Determine risk level based on score."""
        if score <= 3:
            return RiskLevel.EFFICIENT
        elif score <= 7:
            return RiskLevel.NEEDS_OPTIMIZATION
        else:
            return RiskLevel.HIGH_RISK


class SnortPerformanceEvaluator:
    """
    Main evaluator class that combines parsing and analysis.

    Usage:
        evaluator = SnortPerformanceEvaluator()
        result = evaluator.evaluate_rule(rule_string)
        print(result.to_json())
    """

    def __init__(self):
        self.parser = SnortRuleParser()
        self.analyzer = PerformanceAnalyzer()

    def evaluate_rule(self, rule_text: str) -> EvaluationResult:
        """
        Evaluate a single Snort rule.

        Args:
            rule_text: Raw Snort rule string

        Returns:
            EvaluationResult with performance analysis
        """
        parsed = self.parser.parse_rule(rule_text)
        if not parsed:
            return EvaluationResult(
                score=0,
                risk_level="Parse Error",
                reasons=["Failed to parse rule"],
                suggestions=["Check rule syntax"],
            )

        return self.analyzer.analyze(parsed)

    def evaluate_file(self, filepath: str) -> list:
        """
        Evaluate all rules in a .rules file.

        Args:
            filepath: Path to .rules file

        Returns:
            List of EvaluationResult objects
        """
        results = []
        parsed_rules = self.parser.parse_file(filepath)

        for parsed in parsed_rules:
            result = self.analyzer.analyze(parsed)
            results.append(result)

        return results

    def evaluate_rules(self, rules: list) -> list:
        """
        Evaluate a list of rule strings.

        Args:
            rules: List of raw Snort rule strings

        Returns:
            List of EvaluationResult objects
        """
        return [self.evaluate_rule(rule) for rule in rules]

    def generate_report(self, results: list, output_format: str = "json") -> str:
        """
        Generate a summary report of evaluation results.

        Args:
            results: List of EvaluationResult objects
            output_format: 'json' or 'text'

        Returns:
            Formatted report string
        """
        if output_format == "json":
            report = {
                "summary": {
                    "total_rules": len(results),
                    "efficient": sum(
                        1 for r in results if r.risk_level == RiskLevel.EFFICIENT.value
                    ),
                    "needs_optimization": sum(
                        1
                        for r in results
                        if r.risk_level == RiskLevel.NEEDS_OPTIMIZATION.value
                    ),
                    "high_risk": sum(
                        1 for r in results if r.risk_level == RiskLevel.HIGH_RISK.value
                    ),
                    "average_score": (
                        sum(r.score for r in results) / len(results) if results else 0
                    ),
                },
                "rules": [r.to_dict() for r in results],
            }
            return json.dumps(report, indent=2)
        else:
            lines = [
                "=" * 60,
                "SNORT RULE PERFORMANCE EVALUATION REPORT",
                "=" * 60,
                f"\nTotal Rules Analyzed: {len(results)}",
                f"Efficient (0-3): {sum(1 for r in results if r.risk_level == RiskLevel.EFFICIENT.value)}",
                f"Needs Optimization (4-7): {sum(1 for r in results if r.risk_level == RiskLevel.NEEDS_OPTIMIZATION.value)}",
                f"High Risk (8+): {sum(1 for r in results if r.risk_level == RiskLevel.HIGH_RISK.value)}",
                "\n" + "-" * 60,
                "DETAILED RESULTS",
                "-" * 60,
            ]

            for i, result in enumerate(results, 1):
                lines.append(f"\nRule #{i}:")
                lines.append(f"  Score: {result.score} ({result.risk_level})")
                lines.append(
                    f"  Rule: {result.rule[:80]}..."
                    if len(result.rule) > 80
                    else f"  Rule: {result.rule}"
                )
                if result.reasons:
                    lines.append("  Issues:")
                    for reason in result.reasons:
                        lines.append(f"    - {reason}")
                if result.suggestions:
                    lines.append("  Suggestions:")
                    for suggestion in result.suggestions:
                        lines.append(f"    + {suggestion}")

            return "\n".join(lines)


# Convenience function for quick evaluation
def evaluate(rule: str) -> dict:
    """
    Quick evaluation function for a single rule.

    Args:
        rule: Snort rule string

    Returns:
        Dictionary with evaluation results
    """
    evaluator = SnortPerformanceEvaluator()
    result = evaluator.evaluate_rule(rule)
    return result.to_dict()


if __name__ == "__main__":
    # Example usage
    test_rule = 'alert tcp any any -> any 80 (msg:"Test Rule"; content:"GET"; pcre:"/.*user=.*/i"; sid:1000001;)'

    evaluator = SnortPerformanceEvaluator()
    result = evaluator.evaluate_rule(test_rule)
    print(result.to_json())
