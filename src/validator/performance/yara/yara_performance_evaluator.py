#!/usr/bin/env python3
"""
YARA Rule Performance Evaluator

Analyzes YARA detection rules for potential runtime performance bottlenecks.
Statically inspects rule structure, detects inefficient patterns, measures
complexity, and predicts possible slowdown during scanning.

Author: Claude AI
Version: 1.0.0
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Risk level classification for YARA rules."""

    EFFICIENT = "Fast and Efficient"
    MODERATE = "Moderate - Can be Optimized"
    HIGH_RISK = "High Performance Risk"


@dataclass
class PerformanceIssue:
    """Represents a detected performance issue in a YARA rule."""

    name: str
    cost: int
    description: str
    suggestion: str


@dataclass
class ParsedYaraRule:
    """Parsed components of a YARA rule."""

    name: str
    raw: str
    meta: Dict[str, str] = field(default_factory=dict)
    strings: List[Dict] = field(default_factory=list)
    condition: str = ""
    imports: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Complete evaluation result for a YARA rule."""

    rule_name: str
    score: int
    risk_level: str
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_name": self.rule_name,
            "score": self.score,
            "risk_level": self.risk_level,
            "issues": self.issues,
            "suggestions": self.suggestions,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class YaraRuleParser:
    """
    Parser for YARA rule syntax.
    Extracts rule components for performance analysis.
    """

    # Regex patterns for parsing YARA rules
    IMPORT_PATTERN = re.compile(r'^\s*import\s+"([^"]+)"', re.MULTILINE)

    RULE_PATTERN = re.compile(
        r"(?:^|\n)\s*(?:(?:private|global)\s+)?rule\s+(\w+)"  # rule name
        r"(?:\s*:\s*([\w\s]+))?"  # optional tags
        r"\s*\{",  # opening brace
        re.MULTILINE,
    )

    META_PATTERN = re.compile(
        r"meta\s*:\s*(.*?)(?=strings\s*:|condition\s*:|\Z)", re.DOTALL
    )

    STRINGS_PATTERN = re.compile(r"strings\s*:\s*(.*?)(?=condition\s*:|\Z)", re.DOTALL)

    CONDITION_PATTERN = re.compile(
        r"condition\s*:\s*(.*?)(?=\}\s*(?:rule|\Z)|\Z)", re.DOTALL
    )

    # String definition patterns
    STRING_DEF_PATTERN = re.compile(
        r"\$(\w+)\s*=\s*("
        r'"[^"]*"'  # text string
        r"|\'[^\']*\'"  # text string single quotes
        r"|\{[^}]+\}"  # hex string
        r"|/[^/]+/[ismx]*"  # regex
        r")\s*((?:ascii|wide|nocase|fullword|private|xor|base64|base64wide|\([^)]*\))\s*)*",
        re.MULTILINE,
    )

    def __init__(self):
        self.parsed_rules = []

    def parse_rule(self, rule_text: str) -> List[ParsedYaraRule]:
        """
        Parse YARA rules from text and extract components.

        Args:
            rule_text: Raw YARA rule text (may contain multiple rules)

        Returns:
            List of ParsedYaraRule objects
        """
        parsed_rules = []

        # Extract imports
        imports = self.IMPORT_PATTERN.findall(rule_text)

        # Find all rule definitions
        rule_matches = list(self.RULE_PATTERN.finditer(rule_text))

        for i, match in enumerate(rule_matches):
            rule_name = match.group(1)
            tags = match.group(2).split() if match.group(2) else []

            # Find the end of this rule (start of next rule or end of text)
            start_pos = match.end()
            if i + 1 < len(rule_matches):
                end_pos = rule_matches[i + 1].start()
            else:
                end_pos = len(rule_text)

            rule_body = rule_text[start_pos:end_pos]

            # Find the matching closing brace
            brace_count = 1
            actual_end = 0
            for j, char in enumerate(rule_body):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        actual_end = j
                        break

            if actual_end > 0:
                rule_body = rule_body[:actual_end]

            # Parse meta section
            meta = {}
            meta_match = self.META_PATTERN.search(rule_body)
            if meta_match:
                meta = self._parse_meta(meta_match.group(1))

            # Parse strings section
            strings = []
            strings_match = self.STRINGS_PATTERN.search(rule_body)
            if strings_match:
                strings = self._parse_strings(strings_match.group(1))

            # Parse condition
            condition = ""
            condition_match = self.CONDITION_PATTERN.search(rule_body)
            if condition_match:
                condition = condition_match.group(1).strip()
                # Clean up the condition - remove trailing braces
                condition = re.sub(r"\}\s*$", "", condition).strip()

            # Extract raw rule text
            raw_start = match.start()
            raw_end = start_pos + actual_end + 1 if actual_end > 0 else end_pos
            raw_rule = rule_text[raw_start:raw_end].strip()

            parsed_rules.append(
                ParsedYaraRule(
                    name=rule_name,
                    raw=raw_rule,
                    meta=meta,
                    strings=strings,
                    condition=condition,
                    imports=imports,
                    tags=tags,
                )
            )

        return parsed_rules

    def _parse_meta(self, meta_text: str) -> Dict[str, str]:
        """Parse meta section into dictionary."""
        meta = {}
        # Match key = "value" or key = number
        pattern = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|(\d+|true|false))')
        for match in pattern.finditer(meta_text):
            key = match.group(1)
            value = match.group(2) if match.group(2) else match.group(3)
            meta[key] = value
        return meta

    def _parse_strings(self, strings_text: str) -> List[Dict]:
        """Parse strings section into list of string definitions."""
        strings = []

        for match in self.STRING_DEF_PATTERN.finditer(strings_text):
            string_name = match.group(1)
            string_value = match.group(2)
            modifiers_str = match.group(3) if match.group(3) else ""

            # Determine string type
            if string_value.startswith("{"):
                string_type = "hex"
                value = string_value[1:-1].strip()
            elif string_value.startswith("/"):
                string_type = "regex"
                # Extract regex and flags
                regex_match = re.match(r"/(.+)/([ismx]*)", string_value)
                if regex_match:
                    value = regex_match.group(1)
                    modifiers_str += " " + regex_match.group(2)
                else:
                    value = string_value[1:-1]
            else:
                string_type = "text"
                value = string_value.strip("\"'")

            # Parse modifiers
            modifiers = []
            for mod in [
                "ascii",
                "wide",
                "nocase",
                "fullword",
                "private",
                "xor",
                "base64",
                "base64wide",
            ]:
                if mod in modifiers_str.lower():
                    modifiers.append(mod)

            strings.append(
                {
                    "name": string_name,
                    "type": string_type,
                    "value": value,
                    "modifiers": modifiers,
                    "raw": match.group(0),
                }
            )

        return strings

    def parse_file(self, filepath: str) -> List[ParsedYaraRule]:
        """
        Parse all rules from a .yar/.yara file.

        Args:
            filepath: Path to the YARA file

        Returns:
            List of ParsedYaraRule objects
        """
        with open(filepath, "r") as f:
            content = f.read()
        return self.parse_rule(content)


class PerformanceAnalyzer:
    """
    Analyzes parsed YARA rules for performance issues.

    Scoring System:
    - 0-3: Fast and Efficient
    - 4-7: Moderate - Can be Optimized
    - 8+: High Performance Risk
    """

    # Performance cost constants
    COST_LARGE_STRING = 2  # String > 100 chars
    COST_VERY_LARGE_STRING = 3  # String > 500 chars
    COST_LARGE_HEX = 2  # Hex pattern > 50 bytes
    COST_WILDCARD_HEX = 3  # Hex with many wildcards
    COST_HEAVY_WILDCARD = 5  # >50% wildcards in hex
    COST_REGEX_BASIC = 2  # Basic regex usage
    COST_REGEX_GREEDY = 4  # Greedy patterns like .*
    COST_REGEX_BACKTRACK = 5  # Backtracking patterns
    COST_REGEX_NESTED = 3  # Nested groups
    COST_MULTIPLE_REGEX = 4  # Multiple regex in rule
    COST_MANY_STRINGS = 3  # >25 strings
    COST_EXCESSIVE_STRINGS = 5  # >50 strings
    COST_OVERLAPPING_STRINGS = 2  # Overlapping/duplicate strings
    COST_NO_ENCODING_HINT = 1  # Missing wide/ascii
    COST_UNNECESSARY_FULLWORD = 1  # Fullword on short strings
    COST_EXPENSIVE_MODULE = 3  # pe, math, hash modules
    COST_VERY_EXPENSIVE_MODULE = 4  # cuckoo, elf modules
    COST_COMPLEX_CONDITION = 2  # Deep boolean chains
    COST_VERY_COMPLEX_CONDITION = 4  # Very deep nesting
    COST_LOOP_IN_CONDITION = 3  # for loops in condition
    COST_FILESIZE_CHECK = 1  # filesize without bounds

    # Expensive modules list
    EXPENSIVE_MODULES = {
        "pe": COST_EXPENSIVE_MODULE,
        "elf": COST_VERY_EXPENSIVE_MODULE,
        "macho": COST_EXPENSIVE_MODULE,
        "math": COST_EXPENSIVE_MODULE,
        "hash": COST_EXPENSIVE_MODULE,
        "cuckoo": COST_VERY_EXPENSIVE_MODULE,
        "magic": COST_EXPENSIVE_MODULE,
        "dotnet": COST_EXPENSIVE_MODULE,
    }

    # Greedy regex patterns
    GREEDY_PATTERNS = [
        r"\.\*",  # .* greedy
        r"\.\+",  # .+ greedy
        r"\.\{[0-9,]+\}",  # .{n,m}
    ]

    BACKTRACK_PATTERNS = [
        r"\(\.\*\)\*",  # (.*)*
        r"\(\.\+\)\+",  # (.+)+
        r"\([^)]*\)\{[0-9,]*\}",  # grouped with quantifier
    ]

    # String count thresholds
    STRING_THRESHOLD_MEDIUM = 25
    STRING_THRESHOLD_HIGH = 50

    def __init__(self, string_threshold: int = 25):
        self.string_threshold = string_threshold
        self.issues = []

    def analyze(self, parsed_rule: ParsedYaraRule) -> EvaluationResult:
        """
        Analyze a parsed YARA rule for performance issues.

        Args:
            parsed_rule: ParsedYaraRule object

        Returns:
            EvaluationResult with score, risk level, and recommendations
        """
        self.issues = []
        score = 0

        # Check imports/modules
        score += self._analyze_imports(parsed_rule.imports)

        # Check strings
        score += self._analyze_strings(parsed_rule.strings)

        # Check condition
        score += self._analyze_condition(parsed_rule.condition, parsed_rule.strings)

        # Determine risk level
        risk_level = self._get_risk_level(score)

        return EvaluationResult(
            rule_name=parsed_rule.name,
            score=score,
            risk_level=risk_level.value,
            issues=[issue.description for issue in self.issues],
            suggestions=[issue.suggestion for issue in self.issues],
            details={
                "string_count": len(parsed_rule.strings),
                "import_count": len(parsed_rule.imports),
                "issue_breakdown": [
                    {"name": i.name, "cost": i.cost} for i in self.issues
                ],
            },
        )

    def _analyze_imports(self, imports: List[str]) -> int:
        """Analyze imported modules for performance impact."""
        score = 0

        for imp in imports:
            if imp in self.EXPENSIVE_MODULES:
                cost = self.EXPENSIVE_MODULES[imp]
                self.issues.append(
                    PerformanceIssue(
                        name=f"Expensive Module: {imp}",
                        cost=cost,
                        description=f"Expensive module '{imp}' imported (high runtime load)",
                        suggestion=f"Consider if '{imp}' module is necessary, or limit its usage in condition",
                    )
                )
                score += cost

        return score

    def _analyze_strings(self, strings: List[Dict]) -> int:
        """Analyze string definitions for performance issues."""
        score = 0

        # Check string count
        string_count = len(strings)
        if string_count > self.STRING_THRESHOLD_HIGH:
            self.issues.append(
                PerformanceIssue(
                    name="Excessive Strings",
                    cost=self.COST_EXCESSIVE_STRINGS,
                    description=f"Too many strings ({string_count} total) - excessive memory usage",
                    suggestion="Split rule into multiple modular rules or reduce string count",
                )
            )
            score += self.COST_EXCESSIVE_STRINGS
        elif string_count > self.STRING_THRESHOLD_MEDIUM:
            self.issues.append(
                PerformanceIssue(
                    name="Many Strings",
                    cost=self.COST_MANY_STRINGS,
                    description=f"High string count ({string_count} total) may impact performance",
                    suggestion="Consider reducing strings or splitting into multiple rules",
                )
            )
            score += self.COST_MANY_STRINGS

        # Track for overlap detection
        text_values = []
        regex_count = 0

        for string_def in strings:
            string_type = string_def["type"]
            value = string_def["value"]
            modifiers = string_def["modifiers"]

            if string_type == "text":
                score += self._analyze_text_string(value, modifiers)
                text_values.append(value)

            elif string_type == "hex":
                score += self._analyze_hex_string(value)

            elif string_type == "regex":
                regex_count += 1
                score += self._analyze_regex_string(value)

        # Check for multiple regex patterns
        if regex_count > 1:
            additional_cost = (regex_count - 1) * self.COST_MULTIPLE_REGEX
            self.issues.append(
                PerformanceIssue(
                    name="Multiple Regex Patterns",
                    cost=additional_cost,
                    description=f"Multiple regex patterns ({regex_count}) - high CPU usage",
                    suggestion="Convert some regex to text strings with wildcards, or consolidate patterns",
                )
            )
            score += additional_cost

        # Check for overlapping strings
        overlaps = self._check_string_overlaps(text_values)
        if overlaps:
            self.issues.append(
                PerformanceIssue(
                    name="Overlapping Strings",
                    cost=self.COST_OVERLAPPING_STRINGS,
                    description=f"Overlapping/redundant string patterns detected: {overlaps[:3]}",
                    suggestion="Remove redundant strings or consolidate into single pattern",
                )
            )
            score += self.COST_OVERLAPPING_STRINGS

        return score

    def _analyze_text_string(self, value: str, modifiers: List[str]) -> int:
        """Analyze a text string for performance issues."""
        score = 0

        # Check string length
        if len(value) > 500:
            self.issues.append(
                PerformanceIssue(
                    name="Very Large String",
                    cost=self.COST_VERY_LARGE_STRING,
                    description=f"Very large string constant ({len(value)} chars)",
                    suggestion="Consider breaking into smaller anchor patterns",
                )
            )
            score += self.COST_VERY_LARGE_STRING
        elif len(value) > 100:
            self.issues.append(
                PerformanceIssue(
                    name="Large String",
                    cost=self.COST_LARGE_STRING,
                    description=f"Large string constant ({len(value)} chars)",
                    suggestion="Verify if full string is necessary for detection",
                )
            )
            score += self.COST_LARGE_STRING

        # Check for missing encoding hints (only for longer strings)
        if len(value) >= 4 and not any(m in modifiers for m in ["ascii", "wide"]):
            self.issues.append(
                PerformanceIssue(
                    name="Missing Encoding Hint",
                    cost=self.COST_NO_ENCODING_HINT,
                    description="String without explicit ascii/wide modifier",
                    suggestion="Add 'ascii' or 'wide' modifier to optimize string matching",
                )
            )
            score += self.COST_NO_ENCODING_HINT

        # Check for unnecessary fullword on short strings
        if "fullword" in modifiers and len(value) < 4:
            self.issues.append(
                PerformanceIssue(
                    name="Unnecessary Fullword",
                    cost=self.COST_UNNECESSARY_FULLWORD,
                    description="Fullword modifier on very short string",
                    suggestion="Remove 'fullword' from short strings or extend the pattern",
                )
            )
            score += self.COST_UNNECESSARY_FULLWORD

        return score

    def _analyze_hex_string(self, value: str) -> int:
        """Analyze a hex string for performance issues."""
        score = 0

        # Clean and analyze hex pattern
        clean_hex = re.sub(r"\s+", " ", value).strip()
        bytes_list = clean_hex.split()

        # Count wildcards and total bytes
        wildcard_count = sum(1 for b in bytes_list if "?" in b)
        total_bytes = len(bytes_list)

        # Check for large hex patterns
        if total_bytes > 100:
            self.issues.append(
                PerformanceIssue(
                    name="Large Hex Pattern",
                    cost=self.COST_LARGE_HEX,
                    description=f"Large hex pattern ({total_bytes} bytes)",
                    suggestion="Consider splitting into smaller patterns with 'at' offsets",
                )
            )
            score += self.COST_LARGE_HEX

        # Check wildcard percentage
        if total_bytes > 0:
            wildcard_pct = wildcard_count / total_bytes

            if wildcard_pct > 0.5:
                self.issues.append(
                    PerformanceIssue(
                        name="Heavy Wildcard Hex",
                        cost=self.COST_HEAVY_WILDCARD,
                        description=f"Hex pattern is {wildcard_pct*100:.0f}% wildcards - very slow scanning",
                        suggestion="Add more concrete byte anchors to reduce wildcard ratio",
                    )
                )
                score += self.COST_HEAVY_WILDCARD
            elif wildcard_pct > 0.25:
                self.issues.append(
                    PerformanceIssue(
                        name="Wildcard-Rich Hex",
                        cost=self.COST_WILDCARD_HEX,
                        description=f"Hex pattern has {wildcard_pct*100:.0f}% wildcards",
                        suggestion="Convert wildcard sections to anchoring byte sequences",
                    )
                )
                score += self.COST_WILDCARD_HEX

        # Check for jump patterns that could be expensive
        if re.search(r"\[\d+-\d+\]", value) or re.search(r"\[\d+\-\]", value):
            self.issues.append(
                PerformanceIssue(
                    name="Variable Jump Pattern",
                    cost=self.COST_WILDCARD_HEX,
                    description="Variable-length jump in hex pattern",
                    suggestion="Constrain jump ranges or use fixed offsets where possible",
                )
            )
            score += self.COST_WILDCARD_HEX

        return score

    def _analyze_regex_string(self, value: str) -> int:
        """Analyze a regex string for performance issues."""
        score = 0

        # Basic regex cost
        score += self.COST_REGEX_BASIC
        self.issues.append(
            PerformanceIssue(
                name="Regex Pattern",
                cost=self.COST_REGEX_BASIC,
                description="Regex pattern has inherent performance overhead",
                suggestion="Consider converting to text string with wildcards if possible",
            )
        )

        # Check for greedy patterns
        for pattern in self.GREEDY_PATTERNS:
            if re.search(pattern, value):
                self.issues.append(
                    PerformanceIssue(
                        name="Greedy Regex",
                        cost=self.COST_REGEX_GREEDY,
                        description="Greedy quantifier (.*/.+) causes excessive backtracking",
                        suggestion="Use non-greedy quantifiers (.*?/.+?) or limit with {n,m}",
                    )
                )
                score += self.COST_REGEX_GREEDY
                break

        # Check for backtracking patterns
        for pattern in self.BACKTRACK_PATTERNS:
            if re.search(pattern, value):
                self.issues.append(
                    PerformanceIssue(
                        name="Backtracking Regex",
                        cost=self.COST_REGEX_BACKTRACK,
                        description="Pattern may cause catastrophic backtracking",
                        suggestion="Restructure regex to avoid nested quantifiers",
                    )
                )
                score += self.COST_REGEX_BACKTRACK
                break

        # Check for nested groups
        nested_count = len(re.findall(r"\([^)]*\([^)]*\)", value))
        if nested_count > 0:
            self.issues.append(
                PerformanceIssue(
                    name="Nested Regex Groups",
                    cost=self.COST_REGEX_NESTED,
                    description=f"Nested capturing groups ({nested_count}) increase complexity",
                    suggestion="Flatten groups or use non-capturing groups (?:...)",
                )
            )
            score += self.COST_REGEX_NESTED

        return score

    def _check_string_overlaps(self, text_values: List[str]) -> List[str]:
        """Check for overlapping/duplicate string patterns."""
        overlaps = []
        for i, s1 in enumerate(text_values):
            for j, s2 in enumerate(text_values):
                if i < j and len(s1) > 2 and len(s2) > 2:
                    if s1 in s2 or s2 in s1:
                        overlaps.append(f"'{s1[:20]}...' overlaps with '{s2[:20]}...'")
        return overlaps

    def _analyze_condition(self, condition: str, strings: List[Dict]) -> int:
        """Analyze the condition for performance issues."""
        score = 0

        if not condition:
            return score

        # Check for deep boolean chains
        and_count = len(re.findall(r"\band\b", condition, re.IGNORECASE))
        or_count = len(re.findall(r"\bor\b", condition, re.IGNORECASE))
        total_ops = and_count + or_count

        if total_ops > 15:
            self.issues.append(
                PerformanceIssue(
                    name="Very Complex Condition",
                    cost=self.COST_VERY_COMPLEX_CONDITION,
                    description=f"Very complex boolean logic ({total_ops} operators)",
                    suggestion="Simplify condition or split into multiple rules",
                )
            )
            score += self.COST_VERY_COMPLEX_CONDITION
        elif total_ops > 8:
            self.issues.append(
                PerformanceIssue(
                    name="Complex Condition",
                    cost=self.COST_COMPLEX_CONDITION,
                    description=f"Complex boolean chain ({total_ops} operators)",
                    suggestion="Consider restructuring condition for clarity and performance",
                )
            )
            score += self.COST_COMPLEX_CONDITION

        # Check for loops in condition
        if re.search(r"\bfor\b.*\bin\b", condition, re.IGNORECASE):
            self.issues.append(
                PerformanceIssue(
                    name="Loop in Condition",
                    cost=self.COST_LOOP_IN_CONDITION,
                    description="For loop in condition increases evaluation time",
                    suggestion="Minimize loop iterations or use simpler constructs",
                )
            )
            score += self.COST_LOOP_IN_CONDITION

        # Check for expensive operations
        if "math." in condition or "hash." in condition:
            self.issues.append(
                PerformanceIssue(
                    name="Expensive Condition Operation",
                    cost=self.COST_EXPENSIVE_MODULE,
                    description="Math/hash operations in condition are CPU intensive",
                    suggestion="Use string matches as pre-filter before expensive operations",
                )
            )
            score += self.COST_EXPENSIVE_MODULE

        # Check for unbounded filesize checks
        if re.search(r"\bfilesize\b", condition) and not re.search(
            r"filesize\s*[<>]", condition
        ):
            self.issues.append(
                PerformanceIssue(
                    name="Unbounded Filesize",
                    cost=self.COST_FILESIZE_CHECK,
                    description="Filesize used without bounds check",
                    suggestion="Add filesize bounds to skip large files early",
                )
            )
            score += self.COST_FILESIZE_CHECK

        # Check for 'all of them' or 'any of them' with many strings
        if re.search(r"\b(all|any)\s+of\s+(them|\$\*)", condition):
            if len(strings) > 20:
                self.issues.append(
                    PerformanceIssue(
                        name="All/Any with Many Strings",
                        cost=self.COST_COMPLEX_CONDITION,
                        description=f"'all/any of them' with {len(strings)} strings",
                        suggestion="Consider using numbered conditions like '3 of ($a*)'",
                    )
                )
                score += self.COST_COMPLEX_CONDITION

        return score

    def _get_risk_level(self, score: int) -> RiskLevel:
        """Determine risk level based on score."""
        if score <= 3:
            return RiskLevel.EFFICIENT
        elif score <= 7:
            return RiskLevel.MODERATE
        else:
            return RiskLevel.HIGH_RISK


class YaraPerformanceEvaluator:
    """
    Main evaluator class that combines parsing and analysis.

    Usage:
        evaluator = YaraPerformanceEvaluator()
        results = evaluator.evaluate_rule(rule_text)
        for result in results:
            print(result.to_json())
    """

    def __init__(self, string_threshold: int = 25):
        self.parser = YaraRuleParser()
        self.analyzer = PerformanceAnalyzer(string_threshold)

    def evaluate_rule(self, rule_text: str) -> List[EvaluationResult]:
        """
        Evaluate YARA rules from text.

        Args:
            rule_text: Raw YARA rule text (may contain multiple rules)

        Returns:
            List of EvaluationResult objects
        """
        parsed_rules = self.parser.parse_rule(rule_text)
        results = []

        for parsed in parsed_rules:
            result = self.analyzer.analyze(parsed)
            results.append(result)

        return results

    def evaluate_file(self, filepath: str) -> List[EvaluationResult]:
        """
        Evaluate all rules in a .yar/.yara file.

        Args:
            filepath: Path to YARA file

        Returns:
            List of EvaluationResult objects
        """
        parsed_rules = self.parser.parse_file(filepath)
        return [self.analyzer.analyze(parsed) for parsed in parsed_rules]

    def generate_report(
        self, results: List[EvaluationResult], output_format: str = "json"
    ) -> str:
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
                    "moderate": sum(
                        1 for r in results if r.risk_level == RiskLevel.MODERATE.value
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
                "YARA RULE PERFORMANCE EVALUATION REPORT",
                "=" * 60,
                f"\nTotal Rules Analyzed: {len(results)}",
                f"Fast and Efficient (0-3): {sum(1 for r in results if r.risk_level == RiskLevel.EFFICIENT.value)}",
                f"Moderate (4-7): {sum(1 for r in results if r.risk_level == RiskLevel.MODERATE.value)}",
                f"High Risk (8+): {sum(1 for r in results if r.risk_level == RiskLevel.HIGH_RISK.value)}",
                "\n" + "-" * 60,
                "DETAILED RESULTS",
                "-" * 60,
            ]

            for result in results:
                lines.append(f"\nRule: {result.rule_name}")
                lines.append(f"  Score: {result.score} ({result.risk_level})")
                if result.issues:
                    lines.append("  Issues:")
                    for issue in result.issues[:5]:
                        lines.append(f"    - {issue}")
                    if len(result.issues) > 5:
                        lines.append(f"    ... and {len(result.issues) - 5} more")
                if result.suggestions:
                    lines.append("  Suggestions:")
                    for suggestion in result.suggestions[:3]:
                        lines.append(f"    + {suggestion}")
                    if len(result.suggestions) > 3:
                        lines.append(f"    ... and {len(result.suggestions) - 3} more")

            return "\n".join(lines)


# Convenience function for quick evaluation
def evaluate(rule_text: str) -> List[dict]:
    """
    Quick evaluation function for YARA rules.

    Args:
        rule_text: YARA rule text

    Returns:
        List of dictionaries with evaluation results
    """
    evaluator = YaraPerformanceEvaluator()
    results = evaluator.evaluate_rule(rule_text)
    return [r.to_dict() for r in results]


if __name__ == "__main__":
    # Example usage
    test_rule = """
    rule test_rule {
        strings:
            $a = "test string"
            $b = /pattern.*match/
        condition:
            any of them
    }
    """

    evaluator = YaraPerformanceEvaluator()
    results = evaluator.evaluate_rule(test_rule)
    for result in results:
        print(result.to_json())
