# backend/test_integration.py
# Tests the entire Phase 2 + 3 workflow in one shot
# Run with: python test_integration.py (from inside backend/)

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

print("\n" + "="*60)
print("  INTEGRATION TEST — Phase 2 + 3")
print("="*60)

# -------------------------------------------------------
# TEST 1: Config loads correctly
# -------------------------------------------------------
print("\n[1/6] Testing config...")
try:
    from app.config import SECRET_KEY, DATABASE_URL, ALGORITHM
    assert SECRET_KEY, "SECRET_KEY is empty"
    assert DATABASE_URL, "DATABASE_URL is empty"
    assert ALGORITHM == "HS256"
    print("      PASS — config loaded")
except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# TEST 2: Database connects and tables exist
# -------------------------------------------------------
print("\n[2/6] Testing database...")
try:
    from app.database import engine
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "users" in tables, "users table missing"
    assert "transactions" in tables, "transactions table missing"
    assert "alerts" in tables, "alerts table missing"
    print(f"      PASS — tables found: {tables}")
except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# TEST 3: Models import cleanly
# -------------------------------------------------------
print("\n[3/6] Testing models and schemas...")
try:
    from app.models import User, Transaction, Alert
    from app.schemas import TransactionCreate, TransactionOut, AlertOut, UserCreate, Token
    print("      PASS — all models and schemas imported")
except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# TEST 4: Cyber rules fire correctly
# -------------------------------------------------------
print("\n[4/6] Testing cyber rules (security_rules.py)...")
try:
    from services.security_rules import run_rules

    # HIGH risk transaction — should trigger multiple rules
    high_risk_txn = {
        "user_id"          : "U123",
        "amount"           : 12000,       # triggers high_amount
        "device_id"        : "device_new",# triggers new_device
        "location"         : "Mumbai",
        "receiver_id"      : "R999",      # triggers new_receiver
        "transaction_type" : "transfer",
        "timestamp"        : "2026-01-20 02:14:00"  # triggers odd_time
    }
    result = run_rules(high_risk_txn)

    assert "risk_score" in result,       "missing risk_score"
    assert "risk_level" in result,       "missing risk_level"
    assert "triggered_rules" in result,  "missing triggered_rules"
    assert "recommended_action" in result, "missing recommended_action"
    assert len(result["triggered_rules"]) > 0, "no rules triggered — something is wrong"

    print(f"      PASS — risk_score={result['risk_score']}, "
          f"risk_level={result['risk_level']}, "
          f"rules_fired={result['triggered_rules']}")
except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# TEST 5: Risk engine combines everything
# -------------------------------------------------------
print("\n[5/6] Testing risk engine (risk_engine.py)...")
try:
    from services.risk_engine import evaluate_transaction

    result = evaluate_transaction({
        "user_id"          : "U123",
        "amount"           : 12000,
        "device_id"        : "device_new",
        "location"         : "Mumbai",
        "receiver_id"      : "R999",
        "transaction_type" : "transfer",
        "timestamp"        : "2026-01-20 02:14:00"
    })

    assert "risk_score"         in result
    assert "risk_level"         in result
    assert "ml_score"           in result
    assert "rule_flags"         in result
    assert "recommended_action" in result
    assert "explanation"        in result
    assert result["ml_score"] == 0.0, "ml_score should be 0.0 placeholder"
    assert result["risk_score"] > 0,  "risk_score should be > 0 for this transaction"

    print(f"      PASS — risk_score={result['risk_score']}, "
          f"risk_level={result['risk_level']}, "
          f"ml_score={result['ml_score']}, "
          f"explanation='{result['explanation'][:50]}...'")
except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# TEST 6: DB write and read (save a transaction manually)
# -------------------------------------------------------
print("\n[6/6] Testing DB write and read...")
try:
    from app.database import SessionLocal
    from app.models import Transaction
    from datetime import datetime

    db = SessionLocal()

    # Write a test transaction
    test_txn = Transaction(
        user_id          = "test_user",
        receiver_id      = "R999",
        amount           = 12000.0,
        device_id        = "device_new",
        location         = "Mumbai",
        transaction_type = "transfer",
        status           = "pending",
        risk_score       = 60.0,
        risk_level       = "MEDIUM",
        ml_score         = 0.0,
        rule_flags       = ["high_amount", "new_device"]
    )
    db.add(test_txn)
    db.commit()
    db.refresh(test_txn)

    # Read it back
    fetched = db.query(Transaction).filter(Transaction.id == test_txn.id).first()
    assert fetched is not None,             "transaction not found after save"
    assert fetched.amount == 12000.0,       "amount mismatch"
    assert fetched.risk_level == "MEDIUM",  "risk_level mismatch"
    assert fetched.user_id == "test_user",  "user_id mismatch"

    # Clean up test data
    db.delete(fetched)
    db.commit()
    db.close()

    print("      PASS — transaction saved and retrieved from DB correctly")

except Exception as e:
    print(f"      FAIL — {e}")

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------
print("\n" + "="*60)
print("  TEST COMPLETE")
print("  If all 6 show PASS — Phase 2 and 3 are solid.")
print("  Any FAIL — paste the error here.")
print("="*60 + "\n")