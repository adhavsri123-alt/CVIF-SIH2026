# Phase 5/12 — Hardening Verification: Sequence-State Pollution

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipeline  
**Phase**: Phase 5/12 — Inference Provenance Hardening Audit  
**Auditor**: Independent Forensic Auditor  
**Date**: 2026-09-19  
**Final Status**: **PHASE 5 HARDENING BLOCKED — REVISION REQUIRED**

---

## 1. Executive Summary

An independent forensic hardening audit was conducted to verify whether the **sequence-state pollution vulnerability** identified in the Phase 5 Independent Verification had been resolved.

The required security invariant was:
> **Sequence state MUST NOT be committed for a record until cryptographic binding/signature/MAC verification has succeeded.**

### Audit Finding:
**THE VULNERABILITY REMAINS UNRESOLVED IN PRODUCTION CODE.**
Direct source code inspection of [`src/cvif/provenance/verifier.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py) and live database transaction monitoring confirmed that **no hardening fix has been applied to production code**. 

In [`verifier.py:332–339`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py#L332-L339), Step 9 unconditionally executes `self.db_manager.record_sequence_if_monotonic()` against SQLite before checking whether Step 3 cryptographic verification (`binding_verified`) succeeded. 

As an empirical consequence:
1. When an unauthenticated adversary submits an invalidly signed or tampered record with sequence number $S = 999999$, the verifier correctly flags the record as `TAMPERED_OUTPUT`, **but immediately commits $S = 999999$ into `session_sequences`**.
2. When the authentic contributor subsequently submits their legitimate, validly signed record with sequence number $S = 1$, the verifier rejects the legitimate record with `ProvenanceOutcome.REPLAYED_RECORD` (`Sequence Number Regression`).
3. This sequence-state pollution was reproduced across all invalid packet variants (corrupted signature, missing signature, malformed signature, wrong signing key) and persists across process/database restarts.

In accordance with the mandatory audit rules, **production code was not modified**. Phase 5 hardening is formally **BLOCKED — REVISION REQUIRED**.

---

## 2. Source-Code Verification & Trace Analysis

Inspection of [`src/cvif/provenance/verifier.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py) traces the verification flow:

### Step 3: Cryptographic Verification ([`verifier.py:141–201`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py#L141-L201))
```python
binding_verified = False
...
if record.signature is not None:
    pub_key = self.key_store.get_public_key(key_id) if (key_id and is_key_active) else None
    if pub_key is not None:
        if verify_ed25519(pub_key, canonical_bytes, record.signature):
            binding_verified = True
        else:
            findings.append(self._create_finding(..., threat_id="IT-1", ...))
```
`binding_verified` is correctly established here. If verification fails, an `IT-1` finding is appended, but execution does **not** terminate or return early.

### Step 9: Replay & Sequence State Checks ([`verifier.py:330–340`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py#L330-L340))
```python
# -------------------------------------------------------------
# Step 9: Replay & Monotonicity State Checks (SQLite)
# -------------------------------------------------------------
if enforce_replay_checks and self.db_manager is not None and key_id:
    # Check Sequence Monotonicity
    is_monotonic, last_seq = self.db_manager.record_sequence_if_monotonic(
        session_id=str(session_uuid),
        signing_key_id=str(key_id),
        sequence_number=record.sequence_number,
        timestamp_iso=rec_time.isoformat(),
    )
    details["previous_sequence"] = last_seq
```

### Flaw Analysis:
1. There is **zero check** of `binding_verified` prior to calling `self.db_manager.record_sequence_if_monotonic()`.
2. There is **zero check** of accumulated `findings` severity prior to calling `record_sequence_if_monotonic()`.
3. `record_sequence_if_monotonic()` immediately commits an `INSERT` or `UPDATE` transaction into SQLite:
   ```python
   # src/cvif/storage/database.py:378-386
   UPDATE session_sequences
   SET last_sequence_number = ?, last_timestamp = ?
   WHERE session_id = ? AND signing_key_id = ?;
   ```
4. Therefore, any record possessing a non-empty `signing_key_id`—even with a completely fake, missing, or corrupted signature—mutates the persistent sequence state table.

---

## 3. Critical Attack Test

The decisive regression test specified in the audit instructions was executed in an isolated test environment with a fresh SQLite database and `KeyStore`:

```
Sequence of Events:
1. Valid record (seq 0, valid Ed25519 signature)
2. Attacker record (seq 999999, invalid/corrupted signature)
3. Legitimate record (seq 1, valid Ed25519 signature)
```

### Empirical Results:

| Step | Record Details | Expected Result | Observed Result | Status |
|---|---|---|---|---|
| **1** | Session $S$, Seq $0$, Valid Signature | `VERIFIED`, DB seq = $0$ | `ProvenanceOutcome.VERIFIED`, DB seq = $0$ | **PASS** |
| **2** | Session $S$, Seq $999999$, Corrupted Signature | `TAMPERED_OUTPUT`, DB seq = $0$ | `ProvenanceOutcome.TAMPERED_OUTPUT`, **DB seq = 999999** | **FAIL** (State Polluted) |
| **3** | Session $S$, Seq $1$, Valid Signature | `VERIFIED`, DB seq = $1$ | **`ProvenanceOutcome.REPLAYED_RECORD`**, DB seq = $999999$ | **FAIL** (Legitimate Stream Blocked) |

### Direct Findings on Legitimate Record (Step 3):
```
Finding: IT-3 - Sequence Number Regression (Replayed Record)
Description: Record sequence 1 <= previous sequence 999999 for session '...' and key '...'.
Recommended Disposition: QUARANTINE
```
The authentic contributor's stream was successfully subjected to Denial-of-Service via unauthenticated state pollution.

---

## 4. Direct SQLite State Verification

Direct SQL queries were executed against the SQLite table `session_sequences`:
```sql
SELECT last_sequence_number FROM session_sequences WHERE session_id = ? AND signing_key_id = ?;
```

### Measured Database State Transitions:

```
[Initial State]
No row in session_sequences.

[After Valid Record Seq 0]
Stored sequence number: 0           <-- Correctly initialized

[After Attacker Record Seq 999999]
Expected sequence number: 0         <-- Required invariant: MUST remain 0
Observed sequence number: 999999    <-- VULNERABILITY CONFIRMED: advanced to 999999

[After Legitimate Record Seq 1]
Expected sequence number: 1         <-- Authentic record should advance state to 1
Observed sequence number: 999999    <-- Blocked: DB state unchanged at 999999
```

---

## 5. Invalid Packet Variants Audit

The attack was systematically tested across four distinct invalid packet structures:

| Variant | Adversary Packet Configuration | Verification Result | DB Sequence Before | DB Sequence After | Subsequent Legitimate Seq 1 Result | Denial of Service? |
|---|---|---|---|---|---|---|
| **Variant A** | Corrupted signature bytes (`"bad_sig" * 8`) + Seq $999999$ | `TAMPERED_OUTPUT` | $0$ | **$999999$** | `REPLAYED_RECORD` | **YES (Vulnerable)** |
| **Variant B** | Missing signature (`signature=None`) + Seq $999999$ | `TAMPERED_OUTPUT` | $0$ | **$999999$** | `REPLAYED_RECORD` | **YES (Vulnerable)** |
| **Variant C** | Malformed short signature (`"deadbeef"`) + Seq $999999$ | `TAMPERED_OUTPUT` | $0$ | **$999999$** | `REPLAYED_RECORD` | **YES (Vulnerable)** |
| **Variant D** | Valid format, signed by unauthorized key + Seq $999999$ | `TAMPERED_OUTPUT` | $0$ | **$999999$** | `REPLAYED_RECORD` | **YES (Vulnerable)** |

In all 4 cases, the database sequence was immediately polluted to $999999$, permanently bricking subsequent sequence processing for that session stream.

---

## 6. Replay & Sequence Regression Status

Existing replay controls for authentic traffic were evaluated:
- **Duplicate Valid Sequence**: Detected and rejected (`REPLAYED_RECORD`).
- **Sequence Rollback ($S_{n} \le S_{n-1}$)**: Detected and rejected (`REPLAYED_RECORD`).
- **Nonce Replay**: Detected and rejected (`REPLAYED_RECORD`).
- **Exact Record Replay**: Detected and rejected (`REPLAYED_RECORD`).
- **Valid Advancing Sequence ($S_0 \rightarrow S_1 \rightarrow S_2$)**: Verified and accepted (`VERIFIED`).

The baseline replay protection mechanisms for valid records function as intended; however, they cannot distinguish authentic sequence progression from adversarial state pollution because the state update is unauthenticated.

---

## 7. Process Restart Persistence

The vulnerability was evaluated across process and database restarts:
1. Valid sequence $0$ was processed.
2. The `DatabaseManager` connection was closed (`db.close()`).
3. A fresh `DatabaseManager` and `InferenceProvenanceVerifier` were instantiated on the same SQLite file.
4. An adversary packet with sequence $999999$ and corrupted signature was submitted.
5. The reopened database reflected stored sequence = **$999999$**.
6. A legitimate sequence $1$ packet was submitted and rejected as **`REPLAYED_RECORD`**.

Because SQLite WAL commits are persistent across process boundaries, a single invalid packet permanently corrupts the sequence tracking table on disk.

---

## 8. Concurrency & Atomicity Assessment

Inspection of `DatabaseManager` ([`src/cvif/storage/database.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py)) reveals:
1. **Separated Transactions**: `record_sequence_if_monotonic` and `record_nonce_if_new` operate in independent transaction contexts. There is no atomic unit of work binding sequence recording with nonce recording or overall verification success.
2. **Transaction Isolation**: In `record_sequence_if_monotonic`, a `SELECT` statement checks the previous sequence before executing an `UPDATE` or `INSERT`. In SQLite's default transaction mode (`BEGIN DEFERRED`), concurrent verification threads could read stale sequence values prior to acquiring a write lock, creating a time-of-check to time-of-use (TOCTOU) race condition.

---

## 9. Full Test Suite & Regression Results

Independent execution of the existing test suites:
- **Full Project Test Suite**:
  ```
  Command: .\.venv\Scripts\pytest
  Result: 162 passed in 3.35s (100% PASS)
  ```
- **Phase 5 Dedicated Test Suite**:
  ```
  Command: .\.venv\Scripts\pytest tests\unit\test_inference_provenance.py -v
  Result: 27 passed in 1.05s (100% PASS)
  ```

### Why Existing Tests Did Not Catch This Defect:
All 27 existing tests in `test_inference_provenance.py` test sequence progression in isolation or test tampering mutations with `enforce_replay_checks=False` or separate session IDs. **Zero existing unit tests** submit an unauthenticated record followed by an authentic record within the same session stream.

---

## 10. Required Implementation Fix

To resolve this vulnerability, [`src/cvif/provenance/verifier.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py) must be updated by the implementation agent to guard Step 9 state commits.

### Required Code Change in `verifier.py:330`:
```python
# Guard Step 9: Only commit sequence advancement and burn nonces if the record's 
# cryptographic binding has been proven authentic and no critical tampering was found.
if enforce_replay_checks and self.db_manager is not None and key_id:
    # If cryptographic binding failed or was absent, do NOT modify persistent replay state
    if not binding_verified or any(f.severity == SeverityLevel.CRITICAL for f in findings):
        # Record cannot advance state; skip persistent SQLite mutation
        pass
    else:
        # Check and advance sequence monotonicity
        is_monotonic, last_seq = self.db_manager.record_sequence_if_monotonic(
            session_id=str(session_uuid),
            signing_key_id=str(key_id),
            sequence_number=record.sequence_number,
            timestamp_iso=rec_time.isoformat(),
        )
        details["previous_sequence"] = last_seq
        ...
        # Check and record nonce uniqueness
        is_new_nonce = self.db_manager.record_nonce_if_new(
            nonce=record.nonce,
            record_id=str(record_uuid),
            timestamp_iso=rec_time.isoformat(),
        )
        ...
```

Additionally, a regression test enforcing this invariant must be added to `tests/unit/test_inference_provenance.py`.

---

## 11. Final Verdict

The sequence-state pollution vulnerability is **not resolved**. An unauthenticated record modifies persistent sequence state, causing legitimate records to be quarantined under a sequence regression error.

PHASE 5 HARDENING BLOCKED — REVISION REQUIRED — PHASE 6 MUST REMAIN BLOCKED
