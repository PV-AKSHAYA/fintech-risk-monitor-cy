# =============================================================================
# test_rules.py
# Rule Engine Test Suite
# AI-Assisted Financial Transaction Risk Monitoring System
#
# Author  : Cybersecurity Engineer (you)
# Location: test/test_rules.py
#
# Purpose : Validates every rule function and the full scoring pipeline
#           using 8 carefully designed test cases covering all risk levels
#           and edge cases.
#
# Usage   : Run from your PROJECT ROOT folder:
#           python test/test_rules.py
#
# Folder structure assumed:
#   fintech-risk-monitor-cy/
#   ├── cyber_rules/
#   │   ├── rule_definitions.py
#   │   └── risk_scoring.py
#   ├── ml/dataset/transactions.csv
#   └── test/
#       └── test_rules.py   ← you are here
# =============================================================================

import sys
import os

# =============================================================================
# PATH FIX — allows test_rules.py to import from cyber_rules/
# =============================================================================
# Because test_rules.py is in test/ and our modules are in cyber_rules/,
# we need to tell Python where to find them.
# os.path.dirname(__file__)    → the test/ folder
# os.path.join(..., "..")      → one level up = project root
# os.path.abspath(...)         → converts to absolute path
# sys.path.insert(0, ...)      → adds project root to Python's search path

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

# Now Python can find cyber_rules/ as a package
from cyber_rules.rule_definitions import (
    check_high_amount,
    check_new_device,
    check_new_receiver,
    check_location_change,
    check_odd_time,
    check_transaction_velocity,
    evaluate_transaction
)
from cyber_rules.risk_scoring import score_transaction


# =============================================================================
# TEST INFRASTRUCTURE
# =============================================================================
# Simple test runner — no external libraries needed (no pytest required).
# Tracks pass/fail counts and prints a clean report.

class TestRunner:
    """
    Lightweight test runner that tracks results and prints a summary.
    No external dependencies — works with standard Python only.
    """
    def __init__(self):
        self.passed  = 0
        self.failed  = 0
        self.results = []   # List of (test_name, passed, message)

    def assert_equal(self, test_name, actual, expected, extra_info=""):
        """
        Check if actual == expected. Record pass or fail.

        Parameters:
            test_name  (str) : Human-readable name for this check
            actual          : The value your code produced
            expected        : The value you expected
            extra_info (str): Optional extra context to show on failure
        """
        if actual == expected:
            self.passed += 1
            self.results.append((test_name, True, f"✓ Got: {actual}"))
        else:
            self.failed += 1
            msg = f"✗ Expected: {expected}  |  Got: {actual}"
            if extra_info:
                msg += f"  |  {extra_info}"
            self.results.append((test_name, False, msg))

    def assert_true(self, test_name, condition, extra_info=""):
        """Check if condition is True."""
        if condition:
            self.passed += 1
            self.results.append((test_name, True, "✓ Condition met"))
        else:
            self.failed += 1
            msg = "✗ Condition was False"
            if extra_info:
                msg += f"  |  {extra_info}"
            self.results.append((test_name, False, msg))

    def assert_in(self, test_name, item, collection):
        """Check if item is in collection."""
        if item in collection:
            self.passed += 1
            self.results.append((test_name, True, f"✓ '{item}' found"))
        else:
            self.failed += 1
            self.results.append((test_name, False,
                                  f"✗ '{item}' NOT in {collection}"))

    def assert_not_in(self, test_name, item, collection):
        """Check if item is NOT in collection."""
        if item not in collection:
            self.passed += 1
            self.results.append((test_name, True, f"✓ '{item}' correctly absent"))
        else:
            self.failed += 1
            self.results.append((test_name, False,
                                  f"✗ '{item}' should NOT be in {collection}"))

    def print_summary(self):
        """Print the full test report."""
        total = self.passed + self.failed

        print("\n" + "=" * 65)
        print("  TEST RESULTS SUMMARY")
        print("=" * 65)
        print(f"  Total  : {total}")
        print(f"  Passed : {self.passed}  ✓")
        print(f"  Failed : {self.failed}  ✗")
        print("=" * 65)

        if self.failed == 0:
            print("\n  ALL TESTS PASSED — Rule engine is working correctly.")
        else:
            print(f"\n  {self.failed} TEST(S) FAILED — Review output above.")
        print("=" * 65)


# =============================================================================
# SHARED TEST DATA
# =============================================================================
# One standard user profile used across most tests.
# Tests that need different profiles define their own locally.

STANDARD_USER_PROFILE = {
    "registered_location" : "Delhi",
    "known_devices"       : ["device_U001_A", "device_U001_B"],
    "known_receivers"     : ["R100", "R200", "R300", "R400", "R500"],
    "recent_transactions" : [
        # Only 2 recent transactions — velocity rule will NOT fire by default
        {"timestamp": "2025-06-15 10:00:00"},
        {"timestamp": "2025-06-15 10:05:00"},
    ]
}


# =============================================================================
# TEST SUITE 1 — Individual Rule Tests
# =============================================================================

def test_individual_rules(runner):
    """
    Test each of the 6 rule functions in isolation.
    Each rule is tested for both triggered and not-triggered cases.
    """
    print("\n" + "-" * 65)
    print("  SUITE 1: Individual Rule Tests")
    print("-" * 65)

    # ------------------------------------------------------------------
    # Rule 1: check_high_amount
    # ------------------------------------------------------------------
    print("\n  [R1] check_high_amount()")

    # Should TRIGGER: amount above threshold
    result = check_high_amount({"amount": 15000})
    runner.assert_equal(
        "R1 — High amount triggers (15000 > 10000)",
        result["triggered"], True
    )
    runner.assert_equal(
        "R1 — High amount gives correct points",
        result["risk_points"], 25
    )

    # Should NOT trigger: amount below threshold
    result = check_high_amount({"amount": 5000})
    runner.assert_equal(
        "R1 — Normal amount does NOT trigger (5000 < 10000)",
        result["triggered"], False
    )
    runner.assert_equal(
        "R1 — Normal amount gives 0 points",
        result["risk_points"], 0
    )

    # Edge case: exactly at threshold — should NOT trigger (must be strictly greater)
    result = check_high_amount({"amount": 10000})
    runner.assert_equal(
        "R1 — Exactly at threshold does NOT trigger (10000 == 10000)",
        result["triggered"], False
    )

    # ------------------------------------------------------------------
    # Rule 2: check_new_device
    # ------------------------------------------------------------------
    print("\n  [R2] check_new_device()")

    # Should TRIGGER: device not in known list
    result = check_new_device(
        {"device_id": "attacker_device_999"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R2 — Unknown device triggers",
        result["triggered"], True
    )
    runner.assert_equal(
        "R2 — Unknown device gives correct points",
        result["risk_points"], 20
    )

    # Should NOT trigger: known device
    result = check_new_device(
        {"device_id": "device_U001_A"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R2 — Known device A does NOT trigger",
        result["triggered"], False
    )

    result = check_new_device(
        {"device_id": "device_U001_B"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R2 — Known device B does NOT trigger",
        result["triggered"], False
    )

    # ------------------------------------------------------------------
    # Rule 3: check_new_receiver
    # ------------------------------------------------------------------
    print("\n  [R3] check_new_receiver()")

    # Should TRIGGER: receiver not in known list
    result = check_new_receiver(
        {"receiver_id": "MULE001"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R3 — Unknown receiver triggers",
        result["triggered"], True
    )
    runner.assert_equal(
        "R3 — Unknown receiver gives correct points",
        result["risk_points"], 15
    )

    # Should NOT trigger: known receiver
    result = check_new_receiver(
        {"receiver_id": "R100"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R3 — Known receiver does NOT trigger",
        result["triggered"], False
    )

    # ------------------------------------------------------------------
    # Rule 4: check_location_change
    # ------------------------------------------------------------------
    print("\n  [R4] check_location_change()")

    # Should TRIGGER: different city
    result = check_location_change(
        {"location": "Mumbai"},
        STANDARD_USER_PROFILE   # registered_location = "Delhi"
    )
    runner.assert_equal(
        "R4 — Different city (Mumbai vs Delhi) triggers",
        result["triggered"], True
    )
    runner.assert_equal(
        "R4 — Location change gives correct points",
        result["risk_points"], 20
    )

    # Should NOT trigger: same city
    result = check_location_change(
        {"location": "Delhi"},
        STANDARD_USER_PROFILE
    )
    runner.assert_equal(
        "R4 — Same city (Delhi) does NOT trigger",
        result["triggered"], False
    )

    # ------------------------------------------------------------------
    # Rule 5: check_odd_time
    # ------------------------------------------------------------------
    print("\n  [R5] check_odd_time()")

    # Should TRIGGER: midnight (0)
    result = check_odd_time({"timestamp": "2025-06-15 00:30:00"})
    runner.assert_equal(
        "R5 — Midnight (00:30) triggers",
        result["triggered"], True
    )

    # Should TRIGGER: 3 AM
    result = check_odd_time({"timestamp": "2025-06-15 03:14:00"})
    runner.assert_equal(
        "R5 — 3 AM triggers",
        result["triggered"], True
    )
    runner.assert_equal(
        "R5 — Odd time gives correct points",
        result["risk_points"], 10
    )

    # Should TRIGGER: 5 AM (boundary — inclusive)
    result = check_odd_time({"timestamp": "2025-06-15 05:00:00"})
    runner.assert_equal(
        "R5 — 5 AM (boundary) triggers",
        result["triggered"], True
    )

    # Should NOT trigger: 6 AM (just outside window)
    result = check_odd_time({"timestamp": "2025-06-15 06:00:00"})
    runner.assert_equal(
        "R5 — 6 AM does NOT trigger (outside window)",
        result["triggered"], False
    )

    # Should NOT trigger: midday
    result = check_odd_time({"timestamp": "2025-06-15 14:30:00"})
    runner.assert_equal(
        "R5 — 2 PM does NOT trigger",
        result["triggered"], False
    )

    # Should NOT trigger: 11 PM (23:00 — just before midnight)
    result = check_odd_time({"timestamp": "2025-06-15 23:59:00"})
    runner.assert_equal(
        "R5 — 11:59 PM does NOT trigger",
        result["triggered"], False
    )

    # ------------------------------------------------------------------
    # Rule 6: check_transaction_velocity
    # ------------------------------------------------------------------
    print("\n  [R6] check_transaction_velocity()")

    # Should TRIGGER: 8 transactions in last 10 minutes
    high_velocity_profile = {
        **STANDARD_USER_PROFILE,
        "recent_transactions": [
            {"timestamp": "2025-06-15 02:01:00"},
            {"timestamp": "2025-06-15 02:02:00"},
            {"timestamp": "2025-06-15 02:03:00"},
            {"timestamp": "2025-06-15 02:04:00"},
            {"timestamp": "2025-06-15 02:05:00"},
            {"timestamp": "2025-06-15 02:06:00"},
            {"timestamp": "2025-06-15 02:07:00"},
            {"timestamp": "2025-06-15 02:08:00"},
        ]
    }
    current_tx = {"user_id": "U001", "timestamp": "2025-06-15 02:09:00"}
    result = check_transaction_velocity(current_tx, high_velocity_profile)
    runner.assert_equal(
        "R6 — 8 transactions in 10 min triggers (8 > 5)",
        result["triggered"], True
    )
    runner.assert_equal(
        "R6 — Rapid velocity gives correct points",
        result["risk_points"], 25
    )

    # Should NOT trigger: only 2 transactions in window
    result = check_transaction_velocity(
        {"user_id": "U001", "timestamp": "2025-06-15 10:30:00"},
        STANDARD_USER_PROFILE   # only has 2 recent transactions
    )
    runner.assert_equal(
        "R6 — 2 transactions in 10 min does NOT trigger (2 ≤ 5)",
        result["triggered"], False
    )

    # Should NOT trigger: transactions are OLD (outside 10-min window)
    old_transactions_profile = {
        **STANDARD_USER_PROFILE,
        "recent_transactions": [
            {"timestamp": "2025-06-15 09:00:00"},  # 90 min ago
            {"timestamp": "2025-06-15 09:10:00"},  # 80 min ago
            {"timestamp": "2025-06-15 09:20:00"},  # 70 min ago
            {"timestamp": "2025-06-15 09:30:00"},  # 60 min ago
            {"timestamp": "2025-06-15 09:40:00"},  # 50 min ago
            {"timestamp": "2025-06-15 09:50:00"},  # 40 min ago
        ]
    }
    result = check_transaction_velocity(
        {"user_id": "U001", "timestamp": "2025-06-15 10:30:00"},
        old_transactions_profile
    )
    runner.assert_equal(
        "R6 — Old transactions (outside window) do NOT trigger",
        result["triggered"], False
    )


# =============================================================================
# TEST SUITE 2 — Full Transaction Evaluation (evaluate_transaction)
# =============================================================================

def test_evaluate_transaction(runner):
    """
    Tests the master evaluate_transaction() function with complete
    transaction + user_profile inputs for all three risk levels.
    """
    print("\n" + "-" * 65)
    print("  SUITE 2: evaluate_transaction() Full Pipeline Tests")
    print("-" * 65)

    # ------------------------------------------------------------------
    # Test Case 1: Clean normal transaction — ZERO rules should fire
    # ------------------------------------------------------------------
    print("\n  [TC1] Normal transaction — expect 0 rules, score 0")
    normal_tx = {
        "user_id"     : "U001",
        "amount"      : 2500,                      # Low amount
        "timestamp"   : "2025-06-15 11:00:00",     # Normal hour (11 AM)
        "location"    : "Delhi",                    # Home city
        "device_id"   : "device_U001_A",            # Known device
        "receiver_id" : "R100"                      # Known receiver
    }
    result = evaluate_transaction(normal_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC1 — Risk score is 0",
                        result["risk_score"], 0)
    runner.assert_equal("TC1 — No rules triggered",
                        result["triggered_rules"], [])
    runner.assert_equal("TC1 — user_id preserved",
                        result["user_id"], "U001")

    # ------------------------------------------------------------------
    # Test Case 2: High amount ONLY — one rule fires
    # ------------------------------------------------------------------
    print("\n  [TC2] High amount only — expect 1 rule, score 25")
    high_amount_tx = {
        "user_id"     : "U001",
        "amount"      : 20000,                     # HIGH amount → R1 fires
        "timestamp"   : "2025-06-15 11:00:00",     # Normal hour
        "location"    : "Delhi",                    # Same city
        "device_id"   : "device_U001_A",            # Known device
        "receiver_id" : "R100"                      # Known receiver
    }
    result = evaluate_transaction(high_amount_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC2 — Score is 25",
                        result["risk_score"], 25)
    runner.assert_in   ("TC2 — high_amount rule triggered",
                        "high_amount", result["triggered_rules"])
    runner.assert_not_in("TC2 — new_device NOT triggered",
                        "new_device", result["triggered_rules"])

    # ------------------------------------------------------------------
    # Test Case 3: New device ONLY — one rule fires
    # ------------------------------------------------------------------
    print("\n  [TC3] New device only — expect 1 rule, score 20")
    new_device_tx = {
        "user_id"     : "U001",
        "amount"      : 500,                       # Normal amount
        "timestamp"   : "2025-06-15 11:00:00",     # Normal hour
        "location"    : "Delhi",                    # Same city
        "device_id"   : "brand_new_device_xyz",     # NEW device → R2 fires
        "receiver_id" : "R100"                      # Known receiver
    }
    result = evaluate_transaction(new_device_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC3 — Score is 20",
                        result["risk_score"], 20)
    runner.assert_in   ("TC3 — new_device rule triggered",
                        "new_device", result["triggered_rules"])
    runner.assert_not_in("TC3 — high_amount NOT triggered",
                        "high_amount", result["triggered_rules"])

    # ------------------------------------------------------------------
    # Test Case 4: Multiple rapid transactions — velocity fires
    # ------------------------------------------------------------------
    print("\n  [TC4] Rapid transactions — expect velocity rule, score 25")
    rapid_profile = {
        **STANDARD_USER_PROFILE,
        "recent_transactions": [
            {"timestamp": "2025-06-15 14:01:00"},
            {"timestamp": "2025-06-15 14:02:00"},
            {"timestamp": "2025-06-15 14:03:00"},
            {"timestamp": "2025-06-15 14:04:00"},
            {"timestamp": "2025-06-15 14:05:00"},
            {"timestamp": "2025-06-15 14:06:00"},
            {"timestamp": "2025-06-15 14:07:00"},
        ]
    }
    rapid_tx = {
        "user_id"     : "U001",
        "amount"      : 800,                       # Normal amount
        "timestamp"   : "2025-06-15 14:08:00",     # Normal hour
        "location"    : "Delhi",                    # Same city
        "device_id"   : "device_U001_A",            # Known device
        "receiver_id" : "R100"                      # Known receiver
    }
    result = evaluate_transaction(rapid_tx, rapid_profile)

    runner.assert_in   ("TC4 — rapid_velocity triggered",
                        "rapid_velocity", result["triggered_rules"])
    runner.assert_equal("TC4 — Score is 25",
                        result["risk_score"], 25)

    # ------------------------------------------------------------------
    # Test Case 5: Full ATO pattern — all 5 primary rules fire
    # ------------------------------------------------------------------
    print("\n  [TC5] Full ATO pattern — expect high score, multiple rules")
    ato_tx = {
        "user_id"     : "U001",
        "amount"      : 45000,                     # HIGH amount   → +25
        "timestamp"   : "2025-06-15 02:30:00",     # Odd time      → +10
        "location"    : "Kolkata",                  # New city      → +20
        "device_id"   : "attacker_device_1234",     # New device    → +20
        "receiver_id" : "MULE007"                   # New receiver  → +15
    }
    result = evaluate_transaction(ato_tx, STANDARD_USER_PROFILE)

    runner.assert_true ("TC5 — Score ≥ 80 (ATO pattern)",
                        result["risk_score"] >= 80,
                        f"Actual score: {result['risk_score']}")
    runner.assert_in   ("TC5 — high_amount fired",
                        "high_amount", result["triggered_rules"])
    runner.assert_in   ("TC5 — new_device fired",
                        "new_device", result["triggered_rules"])
    runner.assert_in   ("TC5 — location_change fired",
                        "location_change", result["triggered_rules"])
    runner.assert_in   ("TC5 — odd_time fired",
                        "odd_time", result["triggered_rules"])
    runner.assert_in   ("TC5 — new_receiver fired",
                        "new_receiver", result["triggered_rules"])

    # Score cap check: even if all 6 rules fire (115 pts), max is 100
    runner.assert_true ("TC5 — Score never exceeds 100 (cap enforced)",
                        result["risk_score"] <= 100)


# =============================================================================
# TEST SUITE 3 — Full Scoring Pipeline (score_transaction)
# =============================================================================

def test_score_transaction(runner):
    """
    Tests the complete score_transaction() pipeline which adds
    risk_level, recommended_action, and reason explanations.
    """
    print("\n" + "-" * 65)
    print("  SUITE 3: score_transaction() Risk Level & Action Tests")
    print("-" * 65)

    # ------------------------------------------------------------------
    # Test Case 6: Score = 0 → LOW → ALLOW
    # ------------------------------------------------------------------
    print("\n  [TC6] Score 0 → LOW → ALLOW")
    low_tx = {
        "user_id"     : "U001",
        "amount"      : 200,
        "timestamp"   : "2025-06-15 12:00:00",
        "location"    : "Delhi",
        "device_id"   : "device_U001_A",
        "receiver_id" : "R100"
    }
    result = score_transaction(low_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC6 — Risk level is LOW",
                        result["risk_level"], "LOW")
    runner.assert_equal("TC6 — Action is ALLOW",
                        result["recommended_action"], "ALLOW")
    runner.assert_equal("TC6 — No reasons",
                        result["reasons"], [])

    # ------------------------------------------------------------------
    # Test Case 7: Score 40 → MEDIUM → REVIEW
    # ------------------------------------------------------------------
    print("\n  [TC7] Score 40 → MEDIUM → REVIEW")
    medium_tx = {
        "user_id"     : "U001",
        "amount"      : 18000,                     # HIGH amount   +25
        "timestamp"   : "2025-06-15 14:00:00",     # Normal hour
        "location"    : "Delhi",                    # Same city
        "device_id"   : "device_U001_A",            # Known device
        "receiver_id" : "MULE999"                   # New receiver  +15
    }
    result = score_transaction(medium_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC7 — Risk level is MEDIUM",
                        result["risk_level"], "MEDIUM")
    runner.assert_equal("TC7 — Action is REVIEW",
                        result["recommended_action"], "REVIEW")
    runner.assert_equal("TC7 — Score is 40",
                        result["risk_score"], 40)
    runner.assert_true ("TC7 — Reasons list is not empty",
                        len(result["reasons"]) > 0)

    # ------------------------------------------------------------------
    # Test Case 8: Score 90 → HIGH → BLOCK
    # ------------------------------------------------------------------
    print("\n  [TC8] Score 90 → HIGH → BLOCK")
    high_tx = {
        "user_id"     : "U001",
        "amount"      : 75000,                     # HIGH     +25
        "timestamp"   : "2025-06-15 01:30:00",     # Odd time +10
        "location"    : "Bangalore",                # New city +20
        "device_id"   : "attacker_device_9999",     # New dev  +20
        "receiver_id" : "MULE042"                   # New recv +15
    }
    result = score_transaction(high_tx, STANDARD_USER_PROFILE)

    runner.assert_equal("TC8 — Risk level is HIGH",
                        result["risk_level"], "HIGH")
    runner.assert_equal("TC8 — Action is BLOCK",
                        result["recommended_action"], "BLOCK")
    runner.assert_true ("TC8 — Score ≥ 61 (HIGH threshold)",
                        result["risk_score"] >= 61,
                        f"Actual: {result['risk_score']}")
    runner.assert_true ("TC8 — Alert message contains BLOCK",
                        "blocked" in result["alert_message"].lower())
    runner.assert_true ("TC8 — Has 5 reason explanations",
                        len(result["reasons"]) == 5,
                        f"Reasons: {result['reasons']}")


# =============================================================================
# TEST SUITE 4 — CSV Dataset Validation
# =============================================================================

def test_dataset(runner):
    """
    Validates that the transactions.csv file was generated correctly
    and contains the expected columns, row count, and fraud distribution.
    """
    print("\n" + "-" * 65)
    print("  SUITE 4: Dataset Validation (transactions.csv)")
    print("-" * 65)

    # Build the path to transactions.csv from project root
    csv_path = os.path.join(project_root, "ml", "dataset", "transactions.csv")

    # Check file exists
    runner.assert_true(
        "CSV file exists at ml/dataset/transactions.csv",
        os.path.exists(csv_path),
        f"Looked for: {csv_path}"
    )

    if not os.path.exists(csv_path):
        print("  ⚠  Skipping CSV content tests — file not found.")
        return

    # Load the CSV
    try:
        import pandas as pd
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"  ⚠  Could not load CSV: {e}")
        return

    # Check required columns exist
    required_cols = ["user_id", "amount", "device_id",
                     "location", "timestamp", "receiver_id", "is_fraud"]
    for col in required_cols:
        runner.assert_true(
            f"CSV has column: {col}",
            col in df.columns
        )

    # Check row count
    runner.assert_true(
        "CSV has at least 2000 rows",
        len(df) >= 2000,
        f"Actual rows: {len(df)}"
    )

    # Check fraud label is binary (0 or 1 only)
    unique_labels = set(df["is_fraud"].unique())
    runner.assert_true(
        "is_fraud contains only 0 and 1",
        unique_labels.issubset({0, 1}),
        f"Found: {unique_labels}"
    )

    # Check fraud rows exist
    fraud_count = df["is_fraud"].sum()
    runner.assert_true(
        "Dataset contains fraud rows (is_fraud=1)",
        fraud_count > 0,
        f"Fraud count: {fraud_count}"
    )

    # Check normal rows exist
    normal_count = len(df) - fraud_count
    runner.assert_true(
        "Dataset contains normal rows (is_fraud=0)",
        normal_count > 0,
        f"Normal count: {normal_count}"
    )

    # Check amounts are positive
    runner.assert_true(
        "All amounts are positive",
        (df["amount"] > 0).all()
    )

    print(f"\n  Dataset stats: {len(df)} rows | "
          f"{normal_count} normal | {fraud_count} fraud "
          f"({(fraud_count/len(df)*100):.1f}% fraud rate)")


# =============================================================================
# MAIN — Run all test suites
# =============================================================================

if __name__ == "__main__":

    print("=" * 65)
    print("  test_rules.py — Behavioral Rule Engine Test Suite")
    print("  AI-Assisted Financial Transaction Risk Monitoring System")
    print("=" * 65)

    # Create one shared runner instance
    runner = TestRunner()

    # Run all four test suites
    test_individual_rules(runner)
    test_evaluate_transaction(runner)
    test_score_transaction(runner)
    test_dataset(runner)

    # Print the final summary
    runner.print_summary()