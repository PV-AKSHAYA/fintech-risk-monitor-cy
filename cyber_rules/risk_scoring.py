# =============================================================================
# risk_scoring.py
# Risk Scoring Engine
# AI-Assisted Financial Transaction Risk Monitoring System
#
# Author  : Cybersecurity Engineer (you)
# Purpose : Takes the raw output from rule_definitions.py and classifies
#           the risk level, assigns a recommended action, and builds a
#           human-readable explanation for the analyst dashboard.
#
# Depends on : rule_definitions.py (must be in the same folder)
# =============================================================================

# Import the master evaluation function from your rule engine
# Make sure rule_definitions.py is in the same cyber_rules/ folder
from cyber_rules.rule_definitions import evaluate_transaction


# =============================================================================
# CONFIGURATION — Risk Level Thresholds
# =============================================================================
# These are the boundaries that separate LOW / MEDIUM / HIGH risk.
# Stored as constants so you can tune them in one place without
# hunting through the code.

LOW_MAX    = 30   # 0  to 30  → LOW
MEDIUM_MAX = 60   # 31 to 60  → MEDIUM
                  # 61 to 100 → HIGH


# =============================================================================
# FUNCTION 1 — classify_risk_level()
# =============================================================================

def classify_risk_level(risk_score):
    """
    Convert a numeric risk score into a human-readable risk level.

    This is a pure classification function — it only looks at the
    number and returns a label. No transaction data needed here.

    Parameters:
        risk_score (int) : The total risk score from evaluate_transaction()
                           Must be between 0 and 100.

    Returns:
        str : One of "LOW", "MEDIUM", or "HIGH"

    Examples:
        classify_risk_level(15)  → "LOW"
        classify_risk_level(45)  → "MEDIUM"
        classify_risk_level(75)  → "HIGH"
    """
    if risk_score <= LOW_MAX:
        return "LOW"
    elif risk_score <= MEDIUM_MAX:
        return "MEDIUM"
    else:
        return "HIGH"


# =============================================================================
# FUNCTION 2 — get_recommended_action()
# =============================================================================

def get_recommended_action(risk_level):
    """
    Map a risk level to a concrete system action.

    In a real banking system, these actions trigger different workflows:
    - ALLOW   : Transaction proceeds immediately, no friction for user
    - REVIEW  : Transaction held, analyst notified, user may get OTP prompt
    - BLOCK   : Transaction stopped immediately, user alerted, case opened

    Parameters:
        risk_level (str) : "LOW", "MEDIUM", or "HIGH"

    Returns:
        str : One of "ALLOW", "REVIEW", or "BLOCK"

    Examples:
        get_recommended_action("LOW")    → "ALLOW"
        get_recommended_action("MEDIUM") → "REVIEW"
        get_recommended_action("HIGH")   → "BLOCK"
    """
    # A dictionary is cleaner than if/elif when mapping values 1-to-1
    action_map = {
        "LOW"    : "ALLOW",
        "MEDIUM" : "REVIEW",
        "HIGH"   : "BLOCK"
    }

    # .get() returns the value if key exists, "REVIEW" if something unexpected
    return action_map.get(risk_level, "REVIEW")


# =============================================================================
# FUNCTION 3 — build_reason_explanations()
# =============================================================================

def build_reason_explanations(triggered_rules):
    """
    Convert a list of triggered rule names into plain-English explanations.

    Why this matters:
        A dashboard showing "new_device, location_change" is confusing
        to a non-technical analyst. This function translates rule names
        into sentences an analyst can act on immediately.

    Parameters:
        triggered_rules (list) : List of rule name strings that fired
                                 e.g. ["high_amount", "new_device"]

    Returns:
        list : List of plain-English explanation strings

    Example:
        build_reason_explanations(["high_amount", "new_device"])
        → [
            "Transaction amount exceeds safe threshold (> Rs.10,000)",
            "Transaction from a device never used by this user before"
          ]
    """
    # Map each rule name to a clear human-readable explanation
    explanation_map = {
        "high_amount"     : "Transaction amount exceeds safe threshold (> Rs.10,000)",
        "new_device"      : "Transaction from a device never used by this user before",
        "new_receiver"    : "Money sent to a receiver this user has never paid before",
        "location_change" : "Transaction location differs from user's registered city",
        "odd_time"        : "Transaction occurred during suspicious hours (12 AM - 5 AM)",
        "rapid_velocity"  : "User made too many transactions in a short time window"
    }

    # Build the list: for each triggered rule, look up its explanation
    # If somehow an unknown rule name appears, give a generic message
    explanations = [
        explanation_map.get(rule, f"Suspicious pattern detected: {rule}")
        for rule in triggered_rules
    ]

    return explanations


# =============================================================================
# FUNCTION 4 — get_alert_message()
# =============================================================================

def get_alert_message(risk_level, risk_score, transaction):
    """
    Generate a short alert message suitable for SMS/email notification
    or the top of an analyst's dashboard card.

    Parameters:
        risk_level  (str)  : "LOW", "MEDIUM", or "HIGH"
        risk_score  (int)  : Numeric score 0-100
        transaction (dict) : The original transaction dict

    Returns:
        str : A one-line alert message

    Example:
        → "[HIGH ALERT] Transaction of Rs.12000 by U123 blocked.
           Risk score: 100/100. Immediate review required."
    """
    amount  = transaction["amount"]
    user_id = transaction["user_id"]

    messages = {
        "LOW"    : (f"[LOW RISK] Transaction of Rs.{amount} by {user_id} "
                    f"approved. Risk score: {risk_score}/100."),

        "MEDIUM" : (f"[MEDIUM RISK] Transaction of Rs.{amount} by {user_id} "
                    f"flagged for review. Risk score: {risk_score}/100. "
                    f"Step-up authentication recommended."),

        "HIGH"   : (f"[HIGH ALERT] Transaction of Rs.{amount} by {user_id} "
                    f"blocked. Risk score: {risk_score}/100. "
                    f"Immediate review required.")
    }

    return messages.get(risk_level, "Transaction requires manual review.")


# =============================================================================
# MASTER FUNCTION — score_transaction()
# =============================================================================

def score_transaction(transaction, user_profile):
    """
    Master function: Full risk assessment pipeline for one transaction.

    This is what your dashboard and ML integration module will call.
    It runs the entire pipeline in sequence:

        Step 1: evaluate_transaction()  → runs all 6 behavioral rules
        Step 2: classify_risk_level()   → LOW / MEDIUM / HIGH
        Step 3: get_recommended_action()→ ALLOW / REVIEW / BLOCK
        Step 4: build_reason_explanations() → human-readable reasons
        Step 5: get_alert_message()     → notification text
        Step 6: Assemble final result   → one clean dictionary

    Parameters:
        transaction  (dict) : The transaction to assess
        user_profile (dict) : User's behavioral history

    Returns:
        dict : Complete risk assessment result — everything the dashboard
               and downstream systems need in one object.

    Example output:
        {
            "user_id"          : "U123",
            "amount"           : 12000,
            "risk_score"       : 100,
            "risk_level"       : "HIGH",
            "recommended_action": "BLOCK",
            "triggered_rules"  : ["high_amount", "new_device", ...],
            "reasons"          : ["Transaction amount exceeds ...", ...],
            "alert_message"    : "[HIGH ALERT] Transaction of Rs.12000 ...",
            "rule_details"     : [ ... full per-rule breakdown ... ]
        }
    """

    # ------------------------------------------------------------------
    # Step 1: Run the rule engine (from rule_definitions.py)
    # ------------------------------------------------------------------
    evaluation = evaluate_transaction(transaction, user_profile)
    # evaluation now contains:
    # { "user_id", "risk_score", "triggered_rules", "rule_details" }

    # ------------------------------------------------------------------
    # Step 2: Classify the risk level from the numeric score
    # ------------------------------------------------------------------
    risk_score = evaluation["risk_score"]
    risk_level = classify_risk_level(risk_score)

    # ------------------------------------------------------------------
    # Step 3: Determine what action the system should take
    # ------------------------------------------------------------------
    recommended_action = get_recommended_action(risk_level)

    # ------------------------------------------------------------------
    # Step 4: Build plain-English reasons for the analyst
    # ------------------------------------------------------------------
    reasons = build_reason_explanations(evaluation["triggered_rules"])

    # ------------------------------------------------------------------
    # Step 5: Build the alert message for notifications
    # ------------------------------------------------------------------
    alert_message = get_alert_message(risk_level, risk_score, transaction)

    # ------------------------------------------------------------------
    # Step 6: Assemble and return the complete result
    # ------------------------------------------------------------------
    return {
        "user_id"            : evaluation["user_id"],
        "amount"             : transaction["amount"],
        "timestamp"          : transaction["timestamp"],
        "location"           : transaction["location"],
        "risk_score"         : risk_score,
        "risk_level"         : risk_level,
        "recommended_action" : recommended_action,
        "triggered_rules"    : evaluation["triggered_rules"],
        "reasons"            : reasons,
        "alert_message"      : alert_message,
        "rule_details"       : evaluation["rule_details"]
    }


# =============================================================================
# QUICK SMOKE TEST — Tests all three risk levels
# Run with: python risk_scoring.py
# =============================================================================

if __name__ == "__main__":

    import json

    print("=" * 65)
    print("  risk_scoring.py — Testing all three risk levels")
    print("=" * 65)

    # ------------------------------------------------------------------
    # Shared user profile used across all three tests
    # ------------------------------------------------------------------
    user_profile = {
        "registered_location" : "Delhi",
        "known_devices"       : ["device_001", "device_002"],
        "known_receivers"     : ["R100", "R200", "R300"],
        "recent_transactions" : [
            {"timestamp": "2026-01-20 10:01:00"},
            {"timestamp": "2026-01-20 10:02:00"},
        ]
        # Only 2 recent transactions — velocity rule will NOT fire
    }

    # ------------------------------------------------------------------
    # Test Case 1: LOW RISK — normal transaction, no anomalies
    # Expected: 0 rules fire → score = 0 → LOW → ALLOW
    # ------------------------------------------------------------------
    print("\n--- TEST 1: Normal Transaction (Expected: LOW) ---")
    low_tx = {
        "user_id"     : "U001",
        "amount"      : 500,                      # Below threshold
        "timestamp"   : "2026-01-20 10:30:00",    # Daytime hour
        "location"    : "Delhi",                   # Matches registered
        "device_id"   : "device_001",              # Known device
        "receiver_id" : "R100"                     # Known receiver
    }
    result1 = score_transaction(low_tx, user_profile)
    print(f"  Risk Score  : {result1['risk_score']}/100")
    print(f"  Risk Level  : {result1['risk_level']}")
    print(f"  Action      : {result1['recommended_action']}")
    print(f"  Rules Fired : {result1['triggered_rules']}")
    print(f"  Alert       : {result1['alert_message']}")

    # ------------------------------------------------------------------
    # Test Case 2: MEDIUM RISK — some anomalies but not critical
    # Expected: high_amount + new_receiver → score = 40 → MEDIUM → REVIEW
    # ------------------------------------------------------------------
    print("\n--- TEST 2: Suspicious Transaction (Expected: MEDIUM) ---")
    medium_tx = {
        "user_id"     : "U002",
        "amount"      : 15000,                    # High amount → +25
        "timestamp"   : "2026-01-20 14:00:00",    # Normal hour
        "location"    : "Delhi",                   # Same city
        "device_id"   : "device_001",              # Known device
        "receiver_id" : "R999"                     # Unknown receiver → +15
    }
    result2 = score_transaction(medium_tx, user_profile)
    print(f"  Risk Score  : {result2['risk_score']}/100")
    print(f"  Risk Level  : {result2['risk_level']}")
    print(f"  Action      : {result2['recommended_action']}")
    print(f"  Rules Fired : {result2['triggered_rules']}")
    print(f"  Alert       : {result2['alert_message']}")

    # ------------------------------------------------------------------
    # Test Case 3: HIGH RISK — full ATO pattern
    # Expected: 5 rules fire → score = 90 → HIGH → BLOCK
    # ------------------------------------------------------------------
    print("\n--- TEST 3: Account Takeover Pattern (Expected: HIGH) ---")
    high_tx = {
        "user_id"     : "U123",
        "amount"      : 12000,                    # High amount   → +25
        "timestamp"   : "2026-01-20 02:14:00",    # Odd time      → +10
        "location"    : "Mumbai",                  # Location diff → +20
        "device_id"   : "device_new",              # New device    → +20
        "receiver_id" : "R999"                     # New receiver  → +15
    }
    result3 = score_transaction(high_tx, user_profile)
    print(f"  Risk Score  : {result3['risk_score']}/100")
    print(f"  Risk Level  : {result3['risk_level']}")
    print(f"  Action      : {result3['recommended_action']}")
    print(f"  Rules Fired : {result3['triggered_rules']}")
    print(f"  Alert       : {result3['alert_message']}")

    # ------------------------------------------------------------------
    # Print the full structured output for Test 3 (what the dashboard sees)
    # ------------------------------------------------------------------
    print("\n--- Full JSON output (Test 3 — what dashboard receives) ---")
    # Remove rule_details for clean printing
    display = {k: v for k, v in result3.items() if k != "rule_details"}
    print(json.dumps(display, indent=2))

    print("\n" + "=" * 65)
    print("  All tests complete.")
    print("=" * 65)