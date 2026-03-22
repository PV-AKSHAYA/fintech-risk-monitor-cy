import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from cyber_rules.risk_scoring import score_transaction

def run_rules(transaction_data: dict) -> dict:
    user_profile = {
        "registered_location" : transaction_data.get("location", "Unknown"),
        "known_devices"       : [transaction_data.get("device_id", "")],
        "known_receivers"     : [transaction_data.get("receiver_id", "")],
        "recent_transactions" : []
    }

    # Ensure required fields exist
    if "timestamp" not in transaction_data:
        from datetime import datetime
        transaction_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if "receiver_id" not in transaction_data:
        transaction_data["receiver_id"] = "unknown"

    result = score_transaction(transaction_data, user_profile)
    return result