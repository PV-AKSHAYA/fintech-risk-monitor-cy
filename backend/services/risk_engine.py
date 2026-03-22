import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.security_rules import run_rules

def evaluate_transaction(transaction_data: dict) -> dict:
    result = run_rules(transaction_data)

    return {
        "risk_score"         : result["risk_score"],
        "risk_level"         : result["risk_level"],
        "ml_score"           : 0.0,
        "rule_flags"         : result["triggered_rules"],
        "recommended_action" : result["recommended_action"],
        "explanation"        : " | ".join(result["reasons"])
    }