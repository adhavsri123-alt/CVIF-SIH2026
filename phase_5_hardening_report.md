# Phase 5 Hardening Report — Sequence-State Pollution Resolution

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipeline  
**Phase**: Phase 5/12 — Inference Provenance Hardening Audit Fix  
**Target Vulnerability**: Sequence-State Pollution via Unauthenticated Packet Injection  
**Date**: 2026-09-19  

---

## 1. Root Cause Analysis

In the Mode 2 forensic verification gateway ([`src/cvif/provenance/verifier.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py)), Step 9 was responsible for validating sequence monotonicity and updating persistent session sequences in SQLite.

Prior to hardening, Step 9 unconditionally invoked:
```python
is_monotonic, last_seq = self.db_manager.record_sequence_if_monotonic(
    session_id=str(session_uuid),
    signing_key_id=str(key_id),
    sequence_number=record.sequence_number,
    timestamp_iso=rec_time.isoformat(),
)
```
This call occurred **before** evaluating whether the record had successfully passed cryptographic authentication and integrity checks. Consequently:
1. `record_sequence_if_monotonic` immediately executed an `INSERT` or `UPDATE` against the SQLite table `session_sequences`.
2. When an attacker submitted an unauthenticated packet with sequence $S = 999999$ and a forged, missing, corrupted, or unauthorized signature, the verifier accurately flagged the record with an `IT-1` finding and synthesized `ProvenanceOutcome.TAMPERED_OUTPUT`.
3. **However, `session_sequences` had already been advanced to $999999$.**
4. When the authentic contributor subsequently submitted a legitimate, validly signed record with sequence $S = 1$, the verifier observed $1 \le 999999$, generated an `IT-3` finding (`Sequence Number Regression`), and rejected the legitimate record with `ProvenanceOutcome.REPLAYED_RECORD`.
5. This permitted an unauthenticated adversary to permanently brick a contributor's session stream with a single malformed packet (Denial-of-Service via state pollution).

---

## 2. Exact Production-Code Change

The fix was applied strictly to [`src/cvif/provenance/verifier.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py) in Step 9.

### Code Diff:

```diff
--- a/src/cvif/provenance/verifier.py
+++ b/src/cvif/provenance/verifier.py
@@ -332,15 +332,27 @@
         if enforce_replay_checks and self.db_manager is not None and key_id:
-            # Check Sequence Monotonicity
-            is_monotonic, last_seq = self.db_manager.record_sequence_if_monotonic(
-                session_id=str(session_uuid),
-                signing_key_id=str(key_id),
-                sequence_number=record.sequence_number,
-                timestamp_iso=rec_time.isoformat(),
-            )
+            # Query existing sequence state without mutating persistent storage
+            last_seq = self.db_manager.get_last_sequence(str(session_uuid), str(key_id))
             details["previous_sequence"] = last_seq
 
+            # Security Invariant: A record MUST NOT modify persistent sequence state unless:
+            # 1. The record's cryptographic binding has been successfully verified.
+            # 2. The signing key is valid/authorized.
+            # 3. The record has passed the required cryptographic integrity checks.
+            # An invalid, forged, malformed, or unauthenticated record MUST NEVER advance session_sequences.
+            is_crypto_verified = (
+                binding_verified
+                and is_key_active
+                and key_error_type is None
+                and not any(f.threat_id in ("IT-1", "IT-4") for f in findings)
+                and not any(f.severity == SeverityLevel.CRITICAL for f in findings)
+            )
+
+            if is_crypto_verified:
+                # Check Sequence Monotonicity & atomically advance sequence state
+                is_monotonic, prev_seq = self.db_manager.record_sequence_if_monotonic(
+                    session_id=str(session_uuid),
+                    signing_key_id=str(key_id),
+                    sequence_number=record.sequence_number,
+                    timestamp_iso=rec_time.isoformat(),
+                )
+                details["previous_sequence"] = prev_seq
+
                 if not is_monotonic:
```

---

## 3. Verification-Order Explanation

The verification pipeline in [`InferenceProvenanceVerifier.verify_record`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/provenance/verifier.py#L43-L415) now strictly enforces the required verification sequence:

```
Step 1: Schema Version Validation
       ↓
Step 2: Key Resolution against KeyStore (is_key_active, key_error_type)
       ↓
Step 3: Deterministic Cryptographic Binding Verification (Ed25519 / HMAC-SHA256)
       ↓
Step 4: Raw Input Image SHA-256 Hash Integrity Verification (IT-4)
       ↓
Step 5: Model Registry Digest Cross-Reference (IT-2)
       ↓
Step 6: Preprocessing Config Hash Cross-Reference (IT-2)
       ↓
Step 7: Timestamp Plausibility & Skew Validation (IT-3)
       ↓
Step 8: Hash Chain Stream Continuity Linkage (IT-1)
       ↓
Cryptographic Verification Guard Check:
       binding_verified == True
       and is_key_active == True
       and key_error_type is None
       and no critical tampering findings (IT-1, IT-4)
       ↓
Step 9: Replay & Monotonicity State Checks (SQLite)
       • Non-mutating read: get_last_sequence() populates details["previous_sequence"]
       • IF is_crypto_verified:
             Validate sequence monotonicity & atomically advance session_sequences
       • ELSE:
             DO NOT call record_sequence_if_monotonic() (persistent state unmodified)
       • Check and record Nonce Uniqueness (record_nonce_if_new)
       ↓
Synthesis of Provenance Outcome & Disposition
```

Under this control flow, an adversary with an unauthenticated, tampered, forged, or malformed packet fails the cryptographic verification guard. The persistent SQLite sequence table is never invoked for mutation, preserving the stream state intact for legitimate frames.

---

## 4. Regression Tests

Comprehensive regression tests were implemented in [`tests/unit/test_inference_provenance.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/tests/unit/test_inference_provenance.py) under section `4b`:

1. **`test_regression_mandatory_sequence_state_pollution_prevented`**:
   - Isolates a fresh SQLite DB and KeyStore.
   - Emits valid record $S = 0$: Accepted (`VERIFIED`), SQLite sequence is $0$.
   - Emits attacker record $S = 999999$ with corrupted signature: Rejected (`TAMPERED_OUTPUT`), SQLite sequence directly verified to remain $0$.
   - Emits legitimate record $S = 1$: Accepted (`VERIFIED`), SQLite sequence advances to $1$.
2. **`test_regression_variant_a_invalid_signature`**:
   - Tests corrupted signature bytes with sequence $999999$: Rejected, SQLite sequence unchanged at $0$.
3. **`test_regression_variant_b_missing_signature`**:
   - Tests missing signature (`signature=None`) with sequence $999999$: Rejected, SQLite sequence unchanged at $0$.
4. **`test_regression_variant_c_malformed_signature`**:
   - Tests malformed non-hex/short signature with sequence $999999$: Rejected, SQLite sequence unchanged at $0$.
5. **`test_regression_variant_d_unauthorized_signing_key`**:
   - Tests unauthorized signing key with sequence $999999$: Rejected (`UNVERIFIED_KEY`), SQLite sequence unchanged at $0$.
6. **`test_regression_variant_e_full_lifecycle_across_all_invalid_variants`**:
   - Tests the complete lifecycle (valid $0 \rightarrow$ attacker $999999 \rightarrow$ valid $1$) across all four adversary variants in independent sessions.
7. **`test_regression_replay_and_nonce_protection_retained`**:
   - Demonstrates that valid sequence rollback ($S_0$ after $S_1$), duplicate sequence ($S_0$ duplicate), and nonce reuse attacks are still intercepted and rejected as `REPLAYED_RECORD`.

---

## 5. Direct SQLite Sequence-State Results

Direct SQL queries were performed against the SQLite database table `session_sequences`:
```sql
SELECT last_sequence_number FROM session_sequences WHERE session_id = ? AND signing_key_id = ?;
```

### Empirical State Transitions Measured:

| Stage | Operation | Verifier Status | Stored SQLite Sequence | Invariant Status |
|---|---|---|---|---|
| **0** | Initial Database State | N/A | `None` (No row) | Pre-condition satisfied |
| **1** | Valid Record (Seq 0) | `VERIFIED` | `0` | State initialized correctly |
| **2** | Attacker Record (Seq 999999, Bad Sig) | `TAMPERED_OUTPUT` | `0` | **STATE UNMODIFIED (Vulnerability Fixed)** |
| **3** | Legitimate Record (Seq 1) | `VERIFIED` | `1` | **LEGITIMATE ADVANCEMENT PERMITTED** |

The sequence number from the unauthenticated packet had **zero effect** on persistent sequence state.

---

## 6. Transaction & Atomicity Assessment

1. **Transaction Encapsulation**:
   - The method `DatabaseManager.record_sequence_if_monotonic()` encapsulates its check-and-write statements within `with self.transaction() as cur:`, utilizing SQLite transactions that commit on clean exit and execute `conn.rollback()` on exceptions.
2. **Elimination of Unauthenticated Writes**:
   - By gating calls to `record_sequence_if_monotonic()` behind `is_crypto_verified`, no unauthenticated packets enter the transaction.
   - Read-only inspection of the prior sequence is performed using `DatabaseManager.get_last_sequence()`, which issues a `SELECT` query without opening a write transaction or modifying data.
3. **Storage Engine Preservation**:
   - No new persistence mechanisms were introduced.
   - SQLite Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and busy timeouts (`PRAGMA busy_timeout = 5000;`) remain untouched.

---

## 7. Full Test Results

### 1. Dedicated Inference Provenance Suite
```powershell
.\.venv\Scripts\pytest tests\unit\test_inference_provenance.py -v
```
- **Passed**: 34
- **Failed**: 0
- **Skipped**: 0
- **Duration**: 1.62s

### 2. Full System Test Suite
```powershell
.\.venv\Scripts\pytest
```
- **Passed**: 169
- **Failed**: 0
- **Skipped**: 0
- **Duration**: 4.63s

---

## 8. Security Impact

- **Denial-of-Service Defense**: An unauthenticated adversary cannot inject out-of-order or high-numbered sequence packets to poison the verifier's persistent state.
- **State Integrity**: Persistent sequence tracking in `session_sequences` strictly reflects cryptographically authentic records from authorized keys.
- **Replay & Rollback Assurance**: Authentic records continue to be verified against rollback and duplicate replays without interference from dropped or tampered adversarial traffic.

---

## 9. Scope Confirmation

- Fix applied **ONLY** to the sequence-state pollution vulnerability.
- No Phase 6 code (distribution-shift analysis, label flipping, near-duplicate analysis, etc.) was written or modified.
- No modifications were made to canonical serialization, digital signatures, HMAC operations, or nonce semantics.

---

PHASE 5 HARDENING COMPLETE — AWAITING INDEPENDENT VERIFICATION
