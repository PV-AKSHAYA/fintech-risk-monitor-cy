# =============================================================================
# rules_definitions.py
# Behavioral Fraud Detection — Rule Engine
# AI-Assisted Financial Transaction Risk Monitoring System
#
# Author  : Cybersecurity Engineer (you)
# Purpose : Evaluate a financial transaction against 6 behavioral rules
#           and return which rules triggered and how many risk points each adds.
# =============================================================================

# We only need 'datetime' from Python's standard library.
# It lets us parse and work with timestamps (no pip install needed).
from datetime import datetime


# =============================================================================
# HELPER FUNCTION
# =============================================================================

def time_diff_minutes(timestamp_str, reference_str):
    """
    Calculate the difference in minutes between two timestamp strings.

    Why we need this:
        The rapid-velocity rule checks how many transactions happened in
        the last 10 minutes. To do that we need to compare timestamps
        as numbers, not as raw strings.

    Parameters:
        timestamp_str (str) : A past transaction's timestamp
                              e.g. "2026-01-20 02:10:00"
        reference_str (str) : The current transaction's timestamp
                              e.g. "2026-01-20 02:18:00"

    Returns:
        float : Absolute difference in minutes (always positive)

    Example:
        time_diff_minutes("2026-01-20 02:10:00", "2026-01-20 02:18:00")
        → 8.0
    """
    # Define the format our timestamps follow
    fmt = "%Y-%m-%d %H:%M:%S"

    # Convert both strings into Python datetime objects so we can subtract them
    t1 = datetime.strptime(timestamp_str, fmt)
    t2 = datetime.strptime(reference_str, fmt)

    # .total_seconds() gives us the raw difference in seconds
    # We divide by 60 to convert to minutes
    # abs() makes sure we always get a positive number regardless of order
    diff_seconds = abs((t2 - t1).total_seconds())
    return diff_seconds / 60


# =============================================================================
# RULE 1 — HIGH AMOUNT
# =============================================================================

def check_high_amount(transaction, threshold=10000):
    """
    Rule 1: Flag transactions where the amount exceeds a threshold.

    Why this matters (cybersecurity context):
        Most day-to-day transactions are small. A sudden large transfer —
        especially when combined with other anomalies — is a strong fraud signal.
        Real fraud systems use dynamic thresholds based on the user's own
        average. For our project we use a fixed threshold of ₹10,000.

    Parameters:
        transaction (dict) : The current transaction being evaluated
        threshold   (int)  : The amount above which we flag (default ₹10,000)

    Returns:
        dict : {
            "rule"        : name of the rule,
            "triggered"   : True if the rule fired, False otherwise,
            "risk_points" : points added to risk score if triggered
        }

    Example:
        check_high_amount({"amount": 12000})
        → {"rule": "high_amount", "triggered": True, "risk_points": 25}
    """
    # Extract the amount from the transaction dictionary
    amount = transaction["amount"]

    # Check if amount exceeds threshold
    if amount > threshold:
        return {
            "rule": "high_amount",
            "triggered": True,
            "risk_points": 25   # Highest weight — direct financial harm
        }

    # If the rule did NOT trigger, we still return a result
    # with triggered=False and 0 points — this keeps output consistent
    return {
        "rule": "high_amount",
        "triggered": False,
        "risk_points": 0
    }


# =============================================================================
# RULE 2 — NEW DEVICE
# =============================================================================

def check_new_device(transaction, user_profile):
    """
    Rule 2: Flag transactions from a device the user has never used before.

    Why this matters (cybersecurity context):
        Account takeover (ATO) attackers always use their own device —
        a device the victim has never transacted from. This is one of the
        strongest early-warning signals for ATO fraud. Real banks like
        HDFC and SBI check device fingerprints on every transaction.

    Parameters:
        transaction  (dict) : The current transaction
        user_profile (dict) : Contains "known_devices" — a list of device IDs
                              this user has used historically

    Returns:
        dict : Standard rule result with rule name, triggered, risk_points

    Example:
        user_profile = {"known_devices": ["device_001", "device_002"]}
        transaction  = {"device_id": "device_new_xyz"}
        check_new_device(transaction, user_profile)
        → {"rule": "new_device", "triggered": True, "risk_points": 20}
    """
    device_id     = transaction["device_id"]
    known_devices = user_profile["known_devices"]  # This is a list

    # 'not in' checks whether device_id is absent from the list
    if device_id not in known_devices:
        return {
            "rule": "new_device",
            "triggered": True,
            "risk_points": 20   # High weight — strong ATO indicator
        }

    return {
        "rule": "new_device",
        "triggered": False,
        "risk_points": 0
    }


# =============================================================================
# RULE 3 — NEW RECEIVER
# =============================================================================

def check_new_receiver(transaction, user_profile):
    """
    Rule 3: Flag transactions to a receiver the user has never sent money to.

    Why this matters (cybersecurity context):
        Fraudsters transfer money to "mule accounts" — accounts specifically
        set up to receive stolen funds. These are always new/unknown receivers.
        A first-time transfer to an unknown account, especially for a large
        amount, is a classic fraud pattern.

    Parameters:
        transaction  (dict) : The current transaction
        user_profile (dict) : Contains "known_receivers" — list of receiver IDs
                              this user has previously sent money to

    Returns:
        dict : Standard rule result

    Example:
        user_profile = {"known_receivers": ["R100", "R200"]}
        transaction  = {"receiver_id": "R999"}
        check_new_receiver(transaction, user_profile)
        → {"rule": "new_receiver", "triggered": True, "risk_points": 15}
    """
    receiver_id      = transaction["receiver_id"]
    known_receivers  = user_profile["known_receivers"]

    if receiver_id not in known_receivers:
        return {
            "rule": "new_receiver",
            "triggered": True,
            "risk_points": 15   # Medium weight — common in legit use too
        }

    return {
        "rule": "new_receiver",
        "triggered": False,
        "risk_points": 0
    }


# =============================================================================
# RULE 4 — LOCATION CHANGE
# =============================================================================

def check_location_change(transaction, user_profile):
    """
    Rule 4: Flag transactions from a location different from the user's
            registered (home) location.

    Why this matters (cybersecurity context):
        This implements the "impossible travel" detection used by Google,
        Microsoft, and every major bank. If a user's home is Delhi and
        a transaction suddenly comes from Mumbai, either the user is
        traveling (possible) or someone else is using the account (more
        suspicious when combined with other signals).

    Parameters:
        transaction  (dict) : The current transaction, contains "location"
        user_profile (dict) : Contains "registered_location" — user's home city

    Returns:
        dict : Standard rule result

    Example:
        user_profile = {"registered_location": "Delhi"}
        transaction  = {"location": "Mumbai"}
        check_location_change(transaction, user_profile)
        → {"rule": "location_change", "triggered": True, "risk_points": 20}
    """
    current_location     = transaction["location"]
    registered_location  = user_profile["registered_location"]

    # Simple string comparison — if cities don't match, flag it
    if current_location != registered_location:
        return {
            "rule": "location_change",
            "triggered": True,
            "risk_points": 20   # High weight — impossible travel signal
        }

    return {
        "rule": "location_change",
        "triggered": False,
        "risk_points": 0
    }


# =============================================================================
# RULE 5 — ODD TIME TRANSACTION
# =============================================================================

def check_odd_time(transaction):
    """
    Rule 5: Flag transactions that happen between midnight and 5 AM.

    Why this matters (cybersecurity context):
        Automated fraud scripts and attackers in different time zones often
        operate at odd hours. While a low-weight signal on its own,
        it becomes significant when combined with other rules (e.g., new device
        + location change + odd time = very likely ATO).

    Parameters:
        transaction (dict) : Contains "timestamp" as "YYYY-MM-DD HH:MM:SS"

    Returns:
        dict : Standard rule result

    Example:
        transaction = {"timestamp": "2026-01-20 02:14:00"}
        check_odd_time(transaction)
        → {"rule": "odd_time", "triggered": True, "risk_points": 10}
    """
    timestamp = transaction["timestamp"]

    # Parse the timestamp string into a datetime object
    # Then extract just the hour (0–23)
    fmt  = "%Y-%m-%d %H:%M:%S"
    hour = datetime.strptime(timestamp, fmt).hour

    # Midnight (0) through 5 AM (5) is our suspicious window
    if 0 <= hour <= 5:
        return {
            "rule": "odd_time",
            "triggered": True,
            "risk_points": 10   # Low weight alone — modifier signal
        }

    return {
        "rule": "odd_time",
        "triggered": False,
        "risk_points": 0
    }


# =============================================================================
# RULE 6 — RAPID TRANSACTION VELOCITY
# =============================================================================

def check_transaction_velocity(transaction, user_profile, time_window=10, max_allowed=5):
    """
    Rule 6: Flag when a user makes too many transactions in a short time window.

    Why this matters (cybersecurity context):
        After account takeover, attackers drain the account fast through many
        rapid small transactions — a technique called "smurfing" or "structuring".
        Automated fraud scripts can fire 20+ transactions per minute.
        Checking velocity (speed) catches this pattern that amount-based
        rules would miss entirely.

    Parameters:
        transaction  (dict) : Current transaction, needs "user_id" + "timestamp"
        user_profile (dict) : Contains "recent_transactions" — list of past
                              transaction dicts with at least a "timestamp" field
        time_window  (int)  : How many minutes to look back (default: 10)
        max_allowed  (int)  : How many transactions are acceptable (default: 5)

    Returns:
        dict : Standard rule result + "transaction_count" for transparency

    How it works step by step:
        1. Get the current transaction's timestamp
        2. Look at the user's recent transaction history
        3. Count how many happened within the last `time_window` minutes
        4. If count > max_allowed, flag it

    Example:
        If user made 8 transactions in the last 10 minutes → triggered
        → {"rule": "rapid_velocity", "triggered": True, "risk_points": 25}
    """
    current_timestamp    = transaction["timestamp"]
    recent_transactions  = user_profile["recent_transactions"]

    # Count transactions within the time window
    # List comprehension: loop through each past transaction,
    # use our helper function to check if it's within the time window
    recent_count = len([
        t for t in recent_transactions
        if time_diff_minutes(t["timestamp"], current_timestamp) <= time_window
    ])

    if recent_count > max_allowed:
        return {
            "rule"              : "rapid_velocity",
            "triggered"         : True,
            "risk_points"       : 25,          # High weight — automated attack signal
            "transaction_count" : recent_count  # Extra info for the analyst
        }

    return {
        "rule"              : "rapid_velocity",
        "triggered"         : False,
        "risk_points"       : 0,
        "transaction_count" : recent_count
    }


# =============================================================================
# MASTER FUNCTION — evaluate_transaction()
# =============================================================================

def evaluate_transaction(transaction, user_profile):
    """
    Master function: Run ALL 6 rules against a single transaction.

    This is the main entry point for your rule engine. The risk_engine.py
    (Step 5) and any external system will call THIS function — it
    orchestrates all individual rule checks and assembles the final result.

    How it works:
        1. Call each of the 6 rule functions
        2. Collect results into a list
        3. Sum up risk_points from rules that triggered
        4. Collect the names of triggered rules
        5. Cap the total score at 100
        6. Return a clean summary dictionary

    Parameters:
        transaction  (dict) : The transaction to evaluate
        user_profile (dict) : The user's behavioral history

    Returns:
        dict : {
            "user_id"         : who this transaction belongs to,
            "risk_score"      : total points (0–100),
            "triggered_rules" : list of rule names that fired,
            "rule_details"    : full detail of every rule (triggered or not)
        }

    Example output:
        {
            "user_id"         : "U123",
            "risk_score"      : 65,
            "triggered_rules" : ["high_amount", "new_device", "location_change"],
            "rule_details"    : [ ... all 6 rule results ... ]
        }
    """

    # -------------------------------------------------------------------------
    # Step A: Run every rule and collect results into a list
    # -------------------------------------------------------------------------
    # Each function returns a dict like:
    # {"rule": "...", "triggered": True/False, "risk_points": N}

    rule_results = [
        check_high_amount(transaction),
        check_new_device(transaction, user_profile),
        check_new_receiver(transaction, user_profile),
        check_location_change(transaction, user_profile),
        check_odd_time(transaction),
        check_transaction_velocity(transaction, user_profile)
    ]

    # -------------------------------------------------------------------------
    # Step B: Sum risk points from rules that DID trigger
    # -------------------------------------------------------------------------
    # We only add points when triggered == True
    total_score = sum(
        r["risk_points"] for r in rule_results if r["triggered"]
    )

    # -------------------------------------------------------------------------
    # Step C: Cap the score at 100
    # -------------------------------------------------------------------------
    # It's possible to score more than 100 if all rules fire
    # (max theoretical = 115). We cap at 100 for clean percentage display.
    total_score = min(total_score, 100)

    # -------------------------------------------------------------------------
    # Step D: Collect names of triggered rules only
    # -------------------------------------------------------------------------
    triggered_rules = [
        r["rule"] for r in rule_results if r["triggered"]
    ]

    # -------------------------------------------------------------------------
    # Step E: Build and return the final result dictionary
    # -------------------------------------------------------------------------
    return {
        "user_id"         : transaction["user_id"],
        "risk_score"      : total_score,
        "triggered_rules" : triggered_rules,
        "rule_details"    : rule_results      # Full detail for the dashboard
    }


# =============================================================================
# QUICK SMOKE TEST
# When you run this file directly with: python behavior_rules.py
# Python executes the block below. When imported by another file it is skipped.
# =============================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("  behavior_rules.py — Quick Smoke Test")
    print("=" * 60)

    # --- Test transaction (mirrors the example from your project brief) ---
    test_transaction = {
        "user_id"     : "U123",
        "amount"      : 12000,
        "timestamp"   : "2026-01-20 02:14:00",
        "location"    : "Mumbai",
        "device_id"   : "device_new",
        "receiver_id" : "R999"
    }

    # --- User profile: what we know about this user's normal behaviour ---
    test_user_profile = {
        "registered_location" : "Delhi",
        "known_devices"       : ["device_001", "device_002"],
        "known_receivers"     : ["R100", "R200", "R300"],
        "recent_transactions" : [
            {"timestamp": "2026-01-20 02:05:00"},
            {"timestamp": "2026-01-20 02:07:00"},
            {"timestamp": "2026-01-20 02:09:00"},
            {"timestamp": "2026-01-20 02:11:00"},
            {"timestamp": "2026-01-20 02:12:00"},
            {"timestamp": "2026-01-20 02:13:00"},
        ]
        # Note: 6 transactions in the last ~9 minutes → velocity rule fires
    }

    # --- Run the master function ---
    result = evaluate_transaction(test_transaction, test_user_profile)

    # --- Print results ---
    print(f"\nUser ID       : {result['user_id']}")
    print(f"Risk Score    : {result['risk_score']} / 100")
    print(f"Rules Fired   : {result['triggered_rules']}")
    print("\nRule-by-rule breakdown:")
    print("-" * 40)
    for rule in result["rule_details"]:
        status = "TRIGGERED" if rule["triggered"] else "passed"
        pts    = f"+{rule['risk_points']} pts" if rule["triggered"] else "0 pts"
        print(f"  {rule['rule']:<25} {status:<12} {pts}")
    print("-" * 40)
    print(f"  {'TOTAL RISK SCORE':<25} {'':12} {result['risk_score']} pts")
    print("=" * 60)