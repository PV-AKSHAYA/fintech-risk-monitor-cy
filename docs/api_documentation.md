# Transaction Risk Monitor — API Documentation

**Base URL:** `http://127.0.0.1:8000`  
**Auth:** JWT Bearer Token (obtain via `/auth/login`)  
**Interactive Docs:** `http://127.0.0.1:8000/docs`

---

## Authentication

### POST `/auth/register`
Register a new user.

**Request:**
```json
{
  "email": "analyst@test.com",
  "password": "test123",
  "role": "analyst"
}
```
**Response:** `200`
```json
{
  "id": 1,
  "email": "analyst@test.com",
  "role": "analyst"
}
```

---

### POST `/auth/login`
Login and receive a JWT token.

**Request:** `form-data`
```
username: analyst@test.com
password: test123
```
**Response:** `200`
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

---

### GET `/auth/me`
Get currently logged in user.  
**Headers:** `Authorization: Bearer <token>`  
**Response:** `200` — user object

---

## Transactions

> All transaction endpoints require `Authorization: Bearer <token>`

### POST `/transactions/`
Submit a new transaction. Automatically scored by the risk engine.
If risk is MEDIUM or HIGH, an alert is auto-created.

**Request:**
```json
{
  "user_id": "U001",
  "amount": 12000,
  "device_id": "device_new",
  "location": "Mumbai",
  "receiver_id": "R999",
  "transaction_type": "transfer"
}
```
**Response:** `200`
```json
{
  "id": 1,
  "user_id": "U001",
  "amount": 12000,
  "device_id": "device_new",
  "location": "Mumbai",
  "receiver_id": "R999",
  "transaction_type": "transfer",
  "status": "pending",
  "risk_score": 35.0,
  "risk_level": "MEDIUM",
  "ml_score": 0.0,
  "rule_flags": ["high_amount", "odd_time"],
  "timestamp": "2026-01-20T10:30:00"
}
```

---

### GET `/transactions/`
Get all transactions.  
**Response:** `200` — list of transaction objects

---

### GET `/transactions/{id}`
Get a single transaction by ID.  
**Response:** `200` — transaction object  
**Error:** `404` if not found

---

### PATCH `/transactions/{id}/status`
Update transaction status. Analyst marks as safe or suspicious.

**Request:**
```json
{ "status": "suspicious" }
```
**Response:** `200` — updated transaction  
**Error:** `400` if status is not `safe` or `suspicious`

---

## Alerts

> All alert endpoints require `Authorization: Bearer <token>`

### GET `/alerts/`
Get all alerts.  
**Response:** `200` — list of alert objects

---

### GET `/alerts/{id}`
Get a single alert by ID.  
**Response:** `200` — alert object  
**Error:** `404` if not found

---

### PATCH `/alerts/{id}/review`
Mark an alert as reviewed by an analyst.

**Request:**
```json
{ "reviewed_by": "analyst@test.com" }
```
**Response:** `200`
```json
{
  "id": 1,
  "transaction_id": 1,
  "risk_level": "MEDIUM",
  "recommended_action": "REVIEW",
  "explanation": "Transaction amount exceeds safe threshold...",
  "reviewed": "yes",
  "reviewed_by": "analyst@test.com",
  "created_at": "2026-01-20T10:30:00"
}
```

---

## Risk Engine

### How scoring works

Every transaction submitted via `POST /transactions/` is automatically
evaluated by the risk engine before being saved.

**6 behavioral rules are checked:**

| Rule | Trigger | Points |
|---|---|---|
| high_amount | Amount > Rs.10,000 | +25 |
| new_device | Device not in user history | +20 |
| location_change | Location differs from registered city | +20 |
| new_receiver | Receiver not in user history | +15 |
| rapid_velocity | Too many transactions in 10 min | +25 |
| odd_time | Transaction between 12AM - 5AM | +10 |

**Risk levels:**

| Score | Level | Action |
|---|---|---|
| 0 - 30 | LOW | ALLOW |
| 31 - 60 | MEDIUM | REVIEW |
| 61 - 100 | HIGH | BLOCK |

---

## Error Reference

| Code| Meaning |
| 400 | Bad request — invalid input |
| 401 | Unauthorized — missing or invalid token |
| 403 | Forbidden — insufficient role |
| 404 | Not found |
| 422 | Validation error — wrong data format |