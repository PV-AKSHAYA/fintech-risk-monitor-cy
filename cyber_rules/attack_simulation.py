# =============================================================================
# attack_simulation.py
# Attack Simulation Dataset Generator
# AI-Assisted Financial Transaction Risk Monitoring System
#
# Author  : Cybersecurity Engineer (you)
# Purpose : Generate a realistic 2000-row dataset of financial transactions
#           containing both normal behaviour and three fraud attack types.
#           Output is saved as transactions.csv in the same folder.
#
# Usage   : python attack_simulation.py
# Output  : transactions.csv  (2000 rows)
# =============================================================================

import random
import pandas as pd
from datetime import datetime, timedelta

# Fix the random seed so your dataset is reproducible —
# every time you run this script you get the same data.
# This matters for ML training (your teammate needs consistency).
random.seed(42)


# =============================================================================
# SIMULATION CONFIGURATION
# =============================================================================
# All tunable parameters in one place. Change numbers here, not deep in code.

TOTAL_ROWS          = 2000

# How many rows of each transaction type to generate
NORMAL_COUNT        = 1400   # 70% — realistic fraud rate in real systems
ATO_COUNT           = 300    # 15% — Account Takeover
RAPID_COUNT         = 200    # 10% — Rapid velocity / smurfing attack
LARGE_FRAUD_COUNT   = 100    #  5% — Single large transfer fraud

# User pool — 50 simulated users, each with a home city and known devices
NUM_USERS           = 50

# Date range for timestamps — entire year of 2025
START_DATE          = datetime(2025, 1, 1)
END_DATE            = datetime(2025, 12, 31)

# Indian cities for location simulation
CITIES = [
    "Delhi", "Mumbai", "Bangalore", "Chennai", "Hyderabad",
    "Kolkata", "Pune", "Ahmedabad", "Jaipur", "Lucknow"
]

# Receiver pool — 200 simulated receiver accounts
RECEIVER_POOL = [f"R{str(i).zfill(3)}" for i in range(1, 201)]
# e.g. ["R001", "R002", ... "R200"]

# Mule accounts used by fraudsters — separate from normal receivers
MULE_ACCOUNTS = [f"MULE{str(i).zfill(3)}" for i in range(1, 51)]
# e.g. ["MULE001", ... "MULE050"]


# =============================================================================
# STEP 1 — BUILD USER PROFILES
# =============================================================================
# Each user has a home city, 2 known devices, and a set of known receivers.
# This mirrors what a real database would store about each user's history.

def build_user_profiles(num_users):
    """
    Create a dictionary of simulated user profiles.

    Each profile contains:
        - registered_location : user's home city
        - known_devices       : list of 2 device IDs they normally use
        - known_receivers     : 10 receivers they regularly pay

    Parameters:
        num_users (int) : How many users to create

    Returns:
        dict : { "U001": { profile }, "U002": { profile }, ... }
    """
    profiles = {}

    for i in range(1, num_users + 1):
        user_id = f"U{str(i).zfill(3)}"   # U001, U002, ... U050

        profiles[user_id] = {
            "registered_location" : random.choice(CITIES),
            "known_devices"       : [
                f"device_{user_id}_A",
                f"device_{user_id}_B"
            ],
            # Each user regularly pays 10 specific receivers
            "known_receivers"     : random.sample(RECEIVER_POOL, 10)
        }

    return profiles


# =============================================================================
# STEP 2 — TIMESTAMP GENERATOR
# =============================================================================

def random_timestamp(start, end, force_hour=None):
    """
    Generate a random timestamp between start and end dates.

    Parameters:
        start      (datetime) : Earliest possible date
        end        (datetime) : Latest possible date
        force_hour (int)      : If set, forces the hour (used for fraud patterns)
                                e.g. force_hour=2 always generates 2:XX AM

    Returns:
        str : Timestamp string in "YYYY-MM-DD HH:MM:SS" format
    """
    # Calculate total seconds in the date range
    delta_seconds = int((end - start).total_seconds())

    # Pick a random number of seconds from the start
    random_seconds = random.randint(0, delta_seconds)
    timestamp = start + timedelta(seconds=random_seconds)

    # Override the hour if requested (for fraud scenarios)
    if force_hour is not None:
        timestamp = timestamp.replace(
            hour=force_hour,
            minute=random.randint(0, 59),
            second=random.randint(0, 59)
        )

    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# STEP 3 — TRANSACTION GENERATORS (one per type)
# =============================================================================

def generate_normal_transaction(user_id, user_profiles):
    """
    Generate one realistic normal (non-fraud) transaction.

    Normal behaviour pattern:
        - Amount is small to medium (Rs.100 – Rs.8,000)
        - Transaction happens during business/evening hours (8 AM – 10 PM)
        - Uses one of the user's two known devices
        - Comes from the user's registered home city
        - Sent to one of the user's 10 known receivers

    Parameters:
        user_id       (str)  : e.g. "U001"
        user_profiles (dict) : The profile dictionary we built in Step 1

    Returns:
        dict : One row of transaction data with is_fraud = 0
    """
    profile = user_profiles[user_id]

    # Pick a daytime hour — normal users transact between 8 AM and 10 PM
    hour = random.randint(8, 22)

    return {
        "user_id"     : user_id,
        "amount"      : round(random.uniform(100, 8000), 2),
        "device_id"   : random.choice(profile["known_devices"]),   # known device
        "location"    : profile["registered_location"],             # home city
        "timestamp"   : random_timestamp(START_DATE, END_DATE, force_hour=hour),
        "receiver_id" : random.choice(profile["known_receivers"]),  # known receiver
        "is_fraud"    : 0
    }


def generate_ato_transaction(user_id, user_profiles):
    """
    Generate one Account Takeover (ATO) fraud transaction.

    ATO attack pattern:
        - Attacker uses a NEW device (never seen before for this user)
        - Transaction originates from a DIFFERENT city than home
        - Happens at ODD HOURS (midnight to 5 AM)
        - Amount is HIGH (Rs.10,000 – Rs.80,000)
        - Sent to a MULE account (unknown receiver)

    This is the most dangerous fraud type — all 5 signals fire together.

    Parameters:
        user_id       (str)  : The compromised user's ID
        user_profiles (dict) : The profile dictionary

    Returns:
        dict : One row of transaction data with is_fraud = 1
    """
    profile = user_profiles[user_id]

    # Pick a DIFFERENT city than the user's home city
    foreign_cities = [c for c in CITIES if c != profile["registered_location"]]
    attack_city    = random.choice(foreign_cities)

    # Odd hours: between midnight and 5 AM
    attack_hour = random.randint(0, 5)

    return {
        "user_id"     : user_id,
        "amount"      : round(random.uniform(10000, 80000), 2),
        "device_id"   : f"attacker_device_{random.randint(1000, 9999)}",  # new device
        "location"    : attack_city,
        "timestamp"   : random_timestamp(START_DATE, END_DATE, force_hour=attack_hour),
        "receiver_id" : random.choice(MULE_ACCOUNTS),   # mule account
        "is_fraud"    : 1
    }


def generate_rapid_transaction(user_id, user_profiles, base_timestamp):
    """
    Generate one transaction in a rapid-fire burst (smurfing attack).

    Rapid attack pattern:
        - Multiple transactions within a narrow time window (minutes apart)
        - Each goes to a DIFFERENT mule account (to avoid detection)
        - Amounts vary to look less robotic
        - May use a new device (attacker's device)

    The base_timestamp parameter anchors the burst — all transactions
    in a burst will be within minutes of each other.

    Parameters:
        user_id          (str)      : The compromised user
        user_profiles    (dict)     : User profiles
        base_timestamp   (datetime) : The starting point of the burst

    Returns:
        dict : One row of transaction data with is_fraud = 1
    """
    profile = user_profiles[user_id]

    # Each transaction in the burst is 1–8 minutes after the previous one
    offset_minutes = random.randint(1, 8)
    tx_time        = base_timestamp + timedelta(minutes=offset_minutes)

    # Randomly use attacker device OR (less commonly) the user's own device
    # Some ATOs use the original device after credential theft
    use_attacker_device = random.random() < 0.7   # 70% chance attacker uses own device
    device = (
        f"attacker_device_{random.randint(1000, 9999)}"
        if use_attacker_device
        else random.choice(profile["known_devices"])
    )

    return {
        "user_id"     : user_id,
        "amount"      : round(random.uniform(500, 15000), 2),
        "device_id"   : device,
        "location"    : profile["registered_location"],    # may stay in home city
        "timestamp"   : tx_time.strftime("%Y-%m-%d %H:%M:%S"),
        "receiver_id" : random.choice(MULE_ACCOUNTS),      # always to mule accounts
        "is_fraud"    : 1
    }


def generate_large_fraud_transaction(user_id, user_profiles):
    """
    Generate one large single-transfer fraud transaction.

    Large transfer pattern:
        - One very large transaction (Rs.50,000 – Rs.5,00,000)
        - Sent to a mule account
        - May or may not use a new device (sometimes insiders do this)
        - Location may or may not match (varies)

    This models both external fraud AND insider fraud (a compromised
    bank employee making a one-shot large transfer).

    Parameters:
        user_id       (str)  : The user whose account is used
        user_profiles (dict) : User profiles

    Returns:
        dict : One row of transaction data with is_fraud = 1
    """
    profile = user_profiles[user_id]

    # 60% chance the attacker uses a new device, 40% uses existing
    # (models cases where credentials but not device were compromised)
    if random.random() < 0.6:
        device = f"attacker_device_{random.randint(1000, 9999)}"
    else:
        device = random.choice(profile["known_devices"])

    # 50% chance of location change (some insider fraud happens from home city)
    if random.random() < 0.5:
        foreign_cities = [c for c in CITIES if c != profile["registered_location"]]
        location = random.choice(foreign_cities)
    else:
        location = profile["registered_location"]

    # Can happen any time of day (large fraud is not always at odd hours)
    hour = random.randint(0, 23)

    return {
        "user_id"     : user_id,
        "amount"      : round(random.uniform(50000, 500000), 2),
        "device_id"   : device,
        "location"    : location,
        "timestamp"   : random_timestamp(START_DATE, END_DATE, force_hour=hour),
        "receiver_id" : random.choice(MULE_ACCOUNTS),
        "is_fraud"    : 1
    }


# =============================================================================
# STEP 4 — MAIN DATASET GENERATOR
# =============================================================================

def generate_dataset():
    """
    Orchestrate the full dataset generation.

    Generates all four types of transactions, combines them into one
    DataFrame, shuffles the rows (so fraud isn't all at the bottom),
    and saves to transactions.csv.

    Returns:
        pd.DataFrame : The complete 2000-row dataset
    """
    print("=" * 60)
    print("  attack_simulation.py — Dataset Generator")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Build user profiles first
    # ------------------------------------------------------------------
    print(f"\n[1/5] Building {NUM_USERS} user profiles...")
    user_profiles = build_user_profiles(NUM_USERS)
    user_ids      = list(user_profiles.keys())
    print(f"      Done. Users: {user_ids[0]} to {user_ids[-1]}")

    all_transactions = []

    # ------------------------------------------------------------------
    # Generate NORMAL transactions (1400 rows)
    # ------------------------------------------------------------------
    print(f"\n[2/5] Generating {NORMAL_COUNT} normal transactions...")
    for _ in range(NORMAL_COUNT):
        user_id = random.choice(user_ids)
        all_transactions.append(
            generate_normal_transaction(user_id, user_profiles)
        )
    print(f"      Done.")

    # ------------------------------------------------------------------
    # Generate ACCOUNT TAKEOVER transactions (300 rows)
    # ------------------------------------------------------------------
    print(f"\n[3/5] Generating {ATO_COUNT} account takeover transactions...")
    for _ in range(ATO_COUNT):
        user_id = random.choice(user_ids)
        all_transactions.append(
            generate_ato_transaction(user_id, user_profiles)
        )
    print(f"      Done.")

    # ------------------------------------------------------------------
    # Generate RAPID ATTACK transactions (200 rows — in bursts)
    # ------------------------------------------------------------------
    print(f"\n[4/5] Generating {RAPID_COUNT} rapid attack transactions...")

    # Burst size: 8–12 transactions per burst
    # Number of bursts needed to fill 200 rows
    burst_size    = 10
    num_bursts    = RAPID_COUNT // burst_size

    for _ in range(num_bursts):
        # Each burst targets one user
        user_id = random.choice(user_ids)

        # Random start time for this burst
        burst_start = START_DATE + timedelta(
            seconds=random.randint(0, int((END_DATE - START_DATE).total_seconds()))
        )

        # Generate burst_size transactions anchored to this start time
        current_time = burst_start
        for j in range(burst_size):
            tx = generate_rapid_transaction(user_id, user_profiles, current_time)
            all_transactions.append(tx)
            # Each subsequent transaction advances the clock 1–8 minutes
            current_time = current_time + timedelta(minutes=random.randint(1, 8))

    print(f"      Done. ({num_bursts} bursts of ~{burst_size} transactions each)")

    # ------------------------------------------------------------------
    # Generate LARGE FRAUD transactions (100 rows)
    # ------------------------------------------------------------------
    print(f"\n[5/5] Generating {LARGE_FRAUD_COUNT} large fraud transactions...")
    for _ in range(LARGE_FRAUD_COUNT):
        user_id = random.choice(user_ids)
        all_transactions.append(
            generate_large_fraud_transaction(user_id, user_profiles)
        )
    print(f"      Done.")

    # ------------------------------------------------------------------
    # Assemble into a DataFrame
    # ------------------------------------------------------------------
    df = pd.DataFrame(all_transactions)

    # Shuffle rows so fraud transactions are randomly distributed
    # (not all at the bottom — ML models must not learn from row order)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Ensure column order matches specification
    df = df[["user_id", "amount", "device_id", "location",
             "timestamp", "receiver_id", "is_fraud"]]

    return df, user_profiles


# =============================================================================
# STEP 5 — SAVE AND REPORT
# =============================================================================

def save_and_report(df, user_profiles):
    """
    Save the dataset to CSV and print a summary report.

    Parameters:
        df            (DataFrame) : The generated dataset
        user_profiles (dict)      : User profile dictionary (for reference)
    """
    output_path = "transactions.csv"
    df.to_csv(output_path, index=False)

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------
    total        = len(df)
    fraud_count  = df["is_fraud"].sum()
    normal_count = total - fraud_count
    fraud_pct    = (fraud_count / total) * 100

    print("\n" + "=" * 60)
    print("  DATASET SUMMARY")
    print("=" * 60)
    print(f"  Total rows         : {total:,}")
    print(f"  Normal (is_fraud=0): {normal_count:,} ({100 - fraud_pct:.1f}%)")
    print(f"  Fraud  (is_fraud=1): {fraud_count:,}  ({fraud_pct:.1f}%)")
    print(f"\n  Amount stats (all transactions):")
    print(f"    Min    : Rs.{df['amount'].min():,.2f}")
    print(f"    Max    : Rs.{df['amount'].max():,.2f}")
    print(f"    Mean   : Rs.{df['amount'].mean():,.2f}")
    print(f"    Median : Rs.{df['amount'].median():,.2f}")
    print(f"\n  Unique users       : {df['user_id'].nunique()}")
    print(f"  Unique devices     : {df['device_id'].nunique()}")
    print(f"  Unique locations   : {df['location'].nunique()}")
    print(f"  Unique receivers   : {df['receiver_id'].nunique()}")
    print(f"\n  Saved to           : {output_path}")

    # ------------------------------------------------------------------
    # Show a few sample rows
    # ------------------------------------------------------------------
    print("\n  Sample rows (first 5):")
    print("-" * 60)
    print(df.head().to_string(index=False))
    print("-" * 60)

    print("\n  Sample fraud rows (first 3):")
    print("-" * 60)
    fraud_sample = df[df["is_fraud"] == 1].head(3)
    print(fraud_sample.to_string(index=False))
    print("-" * 60)
    print("\n  Dataset generation complete.")
    print("=" * 60)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    # Check pandas is available (it should be after: pip install pandas numpy)
    try:
        import pandas as pd
    except ImportError:
        print("ERROR: pandas not installed.")
        print("Run: pip install pandas numpy")
        exit(1)

    # Generate the dataset
    df, user_profiles = generate_dataset()

    # Save and print report
    save_and_report(df, user_profiles)