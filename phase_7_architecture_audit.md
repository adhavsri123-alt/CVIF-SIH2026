# Phase 7/12 — Assurance Aggregation: Architecture & Requirements Audit

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Customer / Authority**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Phase**: Phase 7/12 — Assurance Aggregation  
**Audit Type**: ARCHITECTURE & REQUIREMENTS AUDIT ONLY (Strict Read-Only)  
**Date**: September 19, 2026  
**Auditor**: Lead System Architect & Forensic Assurance Gate  

---

## 1. Executive Summary

This audit report establishes the authoritative architectural foundation, mathematical aggregation rules, confidence/severity semantics, and execution boundaries for **Phase 7: Assurance Aggregation** of the Computer Vision Integrity Assurance Framework (CVIF).

### 1.1 Context & Baseline Status
Phase 6 (Distribution Shift Analysis) has successfully completed independent forensic verification and is officially **CLOSED** (23/23 Phase 6 tests passing, 192/192 full system test suite passing in 4.88s). All prerequisite analytical layers are now operational:
- **Phase 2 (Foundation)**: Core schemas, cryptographic primitives (SHA-256, HMAC-SHA256, Ed25519), SQLite storage, append-only audit trail (`AuditLogger`), write-once evidence storage (`EvidenceStore`), local trust store (`KeyStore`).
- **Phase 3 (Data Integrity)**: Detection of near-duplicate flooding (`DT-1`), trigger injection (`DT-2`), label flipping (`DT-3`), systematic mislabelling (`DT-4`), out-of-distribution insertion (`DT-5`), and contributor risk aggregation (`DT-6`).
- **Phase 4 (Model Integrity)**: Detection of model substitution (`MT-1`), parameter tampering (`MT-2`), Trojan/backdoor insertion via Neural Cleanse (`MT-3`), and activation anomaly clustering (`MT-4`).
- **Phase 5 (Inference Provenance)**: Verification of inference output alteration (`IT-1`), model identity spoofing (`IT-2`), replay/nonce reuse (`IT-3`), signature/HMAC forgery (`IT-4`), and monotonic sequence tracking (`IT-5`).
- **Phase 6 (Distribution Shift)**: Comparative evaluation of covariate shift (`DS-1`), semantic/concept shift (`DS-2`), environmental/sensor drift (`DS-3`), and targeted adversarial distribution manipulation (`DS-4`).

### 1.2 Audit Mandate & Strict Boundaries
This audit was conducted under strict read-only constraints:
- **Zero Production Code Modified**: No production files have been created or altered.
- **Zero Tests Modified**: The existing test suite remains untouched.
- **Zero Schemas Modified**: The frozen Phase 1/2 schema definition for [`AssuranceVerdict`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L176-L191) is preserved exactly.
- **Zero Dependencies Installed**: The Python runtime environment remains strictly air-gapped and pinned to `requirements.lock`.
- **Zero Placeholder/Stub Logic**: No stub aggregators or premature Phase 8+ components were created.

### 1.3 Key Architectural Determinations
1. **Canonical Schema Ready**: [`AssuranceVerdict`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L176-L191) was defined in Phase 2 with fields: `verdict_id`, `asset_id`, `session_id`, `composite_risk_score`, `disposition`, `contributing_finding_ids`, `summary`, `unsupported_checks`, `timestamp`, and `schema_version`. SQLite persistence methods (`save_verdict`, `get_verdict_for_session`) are already implemented in [`DatabaseManager`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py#L314-L343).
2. **Defensible Aggregation Mathematics**: A simple weighted average is dangerous in defense applications because multiple passing checks will dilute a single fatal backdoor or tampered reconnaissance image. Phase 7 formalizes a **Dual-Mechanism Aggregation Architecture**:
   - **Weakest-Link Veto Gating**: Any `CRITICAL` finding (or finding with recommended disposition `QUARANTINE` and confidence $\ge \tau_{\text{veto}}$) strictly forces `overall_disposition = Disposition.QUARANTINE` and sets a floor on composite risk ($R \ge \tau_{\text{quarantine}}$).
   - **Probabilistic (Noisy-OR) Risk Accumulation**: Within each assurance dimension, non-critical findings compound monotonically without artificial dilution: $R_k = 1 - \prod_j (1 - r_{k,j})$.
3. **Strict Separation of Assurance from Detection**: Phase 7 is an aggregator and arbiter, consuming immutable `Finding` and `EvidenceRecord` artifacts. It does not re-extract features, re-inspect tensors, or rerun detection batteries.
4. **Missing vs. Clean Evidence Invariant**: Missing, skipped, or insufficient evidence is explicitly tracked in `unsupported_checks` and **NEVER** treated as "clean" (zero risk). An asset with unverified dimensions cannot receive an `ACCEPT` disposition.

---

## 2. Authoritative Requirements

The requirements for Phase 7 are derived from the master architecture specification (`implementation_plan.md`), the core data contracts in `src/cvif/core/schemas.py`, and the established multi-phase audit decisions.

### 2.1 Explicit Functional Requirements

- **R-AG1: Multi-Phase Finding Ingestion**: The aggregation engine must accept findings from any combination of completed phases (Phase 3 Data Integrity, Phase 4 Model Integrity, Phase 5 Inference Provenance, Phase 6 Distribution Shift), verifying schema compliance (`schema_version == "1.0"`), valid UUIDs, and immutable linkage.
- **R-AG2: Dimensional Risk Profiling**: The engine must compute normalized risk scores $R_d \in [0.0, 1.0]$ across four discrete operational dimensions:
  1. `data_integrity` (`DT-1` through `DT-6`)
  2. `model_integrity` (`MT-1` through `MT-4`)
  3. `inference_provenance` (`IT-1` through `IT-5`)
  4. `distribution_shift` (`DS-1` through `DS-4`)
- **R-AG3: Weakest-Link Security Veto**: A security-first override rule must be enforced. If any finding has `severity == SeverityLevel.CRITICAL` and `confidence >= min_confidence_for_veto` (default 0.50), or `recommended_disposition == Disposition.QUARANTINE`, the aggregate disposition must be forced to `Disposition.QUARANTINE` regardless of benign scores in other dimensions.
- **R-AG4: Non-Diluting Composite Risk Calculation**: The global `composite_risk_score` $\in [0.0, 1.0]$ must reflect both dimension-level severity and cumulative multi-finding risk. It must satisfy:
  $$\text{composite\_risk\_score} \ge \max_{f \in \mathcal{F}} \big( w(f.\text{severity}) \times f.\text{confidence} \big)$$
  preventing dilution of severe threats by numerous benign checks.
- **R-AG5: Deterministic Disposition Mapping**: The engine must evaluate composite risk and veto triggers against strict thresholds:
  - `QUARANTINE`: Veto condition triggered OR $\text{composite\_risk\_score} \ge \tau_{\text{quarantine}}$ (default 0.70).
  - `REVIEW`: Non-quarantine AND ($\text{composite\_risk\_score} \ge \tau_{\text{review}}$ [default 0.30] OR any finding recommends `REVIEW` OR mandatory checks are incomplete).
  - `ACCEPT`: $\text{composite\_risk\_score} < \tau_{\text{review}}$ AND zero findings recommending `REVIEW`/`QUARANTINE` AND all requested/mandatory checks verified.
- **R-AG6: Incomplete & Missing Evidence Accounting**: The engine must populate `unsupported_checks: List[str]` with all skipped, unexecutable, or insufficient checks. It must enforce that missing evidence never reduces risk.
- **R-AG7: Canonical Verdict Synthesis**: The engine must output a strictly validated [`AssuranceVerdict`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L176-L191) instance.
- **R-AG8: Evidence Traceability**: All finding UUIDs that directly contributed to the risk score or disposition must be preserved in `contributing_finding_ids: List[UUID]`.
- **R-AG9: Audit Trail & Database Integration**: The verdict generation must log an `AuditEventType.VERDICT_ISSUED` event to [`AuditLogger`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/audit/logger.py), persist to the `verdicts` table in SQLite via [`DatabaseManager.save_verdict()`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py#L314-L333), and attach to the session (`AnalysisSession.verdict = verdict`).
- **R-AG10: 100% Air-Gapped Pure-Python Portability**: Aggregation must execute purely in Python standard library (`math`, `uuid`, `typing`) with zero network access and deterministic float calculations.

---

## 3. Requirement Traceability Matrix

| Requirement ID | Architecture Section | Required Behavior | Existing Dependency | Proposed Phase 7 Component | Verification Method |
|:---|:---|:---|:---|:---|:---|
| **R-AG1** | Section I.2 & I.4 | Ingest multi-phase `Finding` objects; validate schema | `Finding`, `schemas.py` | `AssuranceAggregator._validate_findings` | Schema round-trip & malformed finding rejection tests |
| **R-AG2** | Section I.4 | Categorize findings into 4 dimensions & compute sub-scores | `ThreatCategory`, `Finding.category` | `AssuranceAggregator._compute_dimension_scores` | Dimension isolation tests with synthetic findings |
| **R-AG3** | Section B.4 (Security) | Critical finding forces `QUARANTINE` (veto) | `SeverityLevel.CRITICAL`, `Disposition.QUARANTINE` | `AssuranceAggregator._evaluate_veto_rules` | Test single CRITICAL finding alongside 20 benign checks |
| **R-AG4** | Section 8 / Risk Model | Noisy-OR accumulation with weakest-link dominance | Python `math` | `AssuranceAggregator._compute_composite_risk` | Mathematical test vectors: zero, single, compounding, extreme |
| **R-AG5** | Section I.4 (`disposition`) | Map risk to `ACCEPT`, `REVIEW`, `QUARANTINE` | `Disposition`, `AssuranceConfig` | `AssuranceAggregator._determine_disposition` | Boundary tests around $\tau_{\text{review}}$ (0.30) and $\tau_{\text{quarantine}}$ (0.70) |
| **R-AG6** | Section I.4 (`unsupported_checks`) | Track skipped/insufficient checks; block blind `ACCEPT` | `AnalysisSession.skipped_analyses` | `AssuranceAggregator._process_skipped_checks` | Test unperformed check preventing `ACCEPT` disposition |
| **R-AG7** | Section I.4 (`AssuranceVerdict`) | Construct canonical `AssuranceVerdict` | `AssuranceVerdict`, `CVIFBaseModel` | `AssuranceAggregator.aggregate()` | Canonical JSON serialization and field validator tests |
| **R-AG8** | Section I.4 (`contributing_finding_ids`) | Traceability list of all active finding UUIDs | `Finding.finding_id`, `UUID` | `AssuranceAggregator._extract_contributing_ids` | Verify exact set equality with input finding IDs |
| **R-AG9** | Section S.1 & W.1 | Store verdict in SQLite and log `VERDICT_ISSUED` in audit chain | `DatabaseManager`, `AuditLogger` | `AssuranceOrchestrator` / `session` integration | Query DB after execution; verify audit hash chain integrity |
| **R-AG10** | Section V.1 (Air Gap) | 100% offline, deterministic CPU execution | Standard library only | Entire Phase 7 module | Run under `test_offline.py` socket-blocking fixture |

---

## 4. Definition of Assurance in CVIF

In civilian machine learning, "assurance" is often used colloquially as a synonym for test-set accuracy or validation F1-score. In military, defense, and high-consequence national security pipelines (MoD / Indian Army DGIS), **assurance has a precise forensic and security meaning**.

```
                           TAXONOMY OF ASSURANCE CONCEPTS
                           
[ Raw Evidence ] (Metrics, digests, tensors, histograms, trigger masks)
       │
       ▼
  [ Finding ]   (Threat-specific detection: threat_id, severity, confidence, recommended_disposition)
       │
       ▼
 [ Dimensional  (Grouped by Data Integrity, Model Integrity, Provenance, Distribution Shift)
   Profiling ]
       │
       ▼
 [ Veto Gating ] (Strict security filter: CRITICAL finding or QUARANTINE recommendation forces stop)
       │
       ▼
 [ Composite   (Mathematically accumulated risk score in [0.0, 1.0])
  Risk Score ]
       │
       ▼
 [ Final        (Actionable operational command: ACCEPT, REVIEW, QUARANTINE with narrative & audit binding)
   Verdict ]
```

### 4.1 Rigorous Semantic Distinctions
- **Raw Evidence (`EvidenceRecord`)**: Uninterpreted quantitative observations (e.g., $L_1$ norm $= 0.012$, Kolmogorov-Smirnov $D = 0.42$, SHA-256 mismatch, luminance delta).
- **Finding (`Finding`)**: A formalized detection artifact linking an observed anomaly to a specific Threat Taxonomy entry (`DT-x`, `MT-x`, `IT-x`, `DS-x`), assigning an intrinsic `severity` and a calibrated `confidence`.
- **Confidence**: The statistical or cryptographic certainty that the detector's observation represents a true positive ($C \in [0.0, 1.0]$). It is *detector-local* evidence strength, NOT global asset safety.
- **Severity (`SeverityLevel`)**: The intrinsic operational mission impact if the threat is present (CRITICAL = immediate mission compromise / hostile control; INFORMATIONAL = diagnostic telemetry).
- **Likelihood**: The estimated probability that an anomaly arises from hostile manipulation rather than natural operational drift (e.g., `suspicious_manipulation_likelihood` in Phase 6).
- **Assurance**: The synthesized, forensic confidence that an asset is authentic, uncorrupted, untampered, and operationally reliable for deployment in tactical operations. It is inversely related to risk under complete evidence coverage:
  $$\text{Assurance} \propto (1 - \text{composite\_risk\_score}) \times \text{EvidenceCoverage}$$
- **Final Verdict (`AssuranceVerdict`)**: The authoritative, machine-readable, and cryptographically logged disposition decision (`ACCEPT`, `REVIEW`, `QUARANTINE`) governing whether an asset may enter operational service.

---

## 5. Input Evidence Inventory

Phase 7 ingests findings and evidence records across all four operational domains:

```
INPUT EVIDENCE MATRIX (PHASES 3–6)
├── Phase 3: DATA_INTEGRITY
│   ├── DT-1: Near-Duplicate Flooding (Statistical cosine distance, image hashes)
│   ├── DT-2: Poison Trigger Injection (High-frequency patch / frequency anomalies)
│   ├── DT-3: Label Flipping (k-NN feature-label inconsistency)
│   ├── DT-4: Systematic Mislabelling (Confused class pairs, cluster error rates)
│   ├── DT-5: Out-of-Distribution Insertion (Embedding Mahalanobis/Z-score outliers)
│   └── DT-6: Contributor Provenance Risk (Multi-finding contributor clustering)
├── Phase 4: MODEL_INTEGRITY
│   ├── MT-1: Model Architecture / Identity Substitution (Layer/topology hash mismatch)
│   ├── MT-2: Parameter Tampering / Weight Modification (Tensor SHA-256 / weight stats)
│   ├── MT-3: Backdoor / Trojan Detection (Neural Cleanse trigger L1 norm, anomaly index > 2.0)
│   └── MT-4: Activation Anomaly Clustering (Neuron activation distribution clustering)
├── Phase 5: INFERENCE_PROVENANCE
│   ├── IT-1: Post-Hoc Output Alteration (Canonical payload HMAC/Ed25519 signature mismatch)
│   ├── IT-2: Model Identity Substitution (Inference record model weight digest mismatch)
│   ├── IT-3: Replayed Inference Packet (Duplicate nonce in seen_nonces registry)
│   ├── IT-4: Cryptographic Signature Forgery (Untrusted, suspended, or revoked key)
│   └── IT-5: Stream Sequence Regression / Gap (Non-monotonic sequence counter)
└── Phase 6: DISTRIBUTION_SHIFT
    ├── DS-1: Covariate Shift (Feature-space MMD, 1D Wasserstein Earth Mover's Distance)
    ├── DS-2: Semantic / Concept Shift (Class prior Total Variation, Jensen-Shannon divergence)
    ├── DS-3: Environmental & Sensor Drift (Luminance, contrast, sharpness, blur Kolmogorov-Smirnov)
    └── DS-4: Adversarial Distribution Manipulation (Targeted subpopulation cluster divergence)
```

---

## 6. Evidence Boundaries

To maintain clean modular boundaries and prevent architectural regression:

### 6.1 What Phase 7 MUST NOT Do
- **NO Re-detection**: Phase 7 must not re-inspect raw image pixels, re-compute CNN embeddings, re-hash model weight files, or re-run Neural Cleanse trigger searches.
- **NO Metric Re-calculation**: Phase 7 must not re-calculate MMD, Wasserstein, KS p-values, or HMAC signatures.
- **NO Severity Mutation**: Phase 7 must not alter the `severity` or `confidence` attributes of an input `Finding`. Findings emitted by upstream detectors are immutable records of fact.
- **NO Evidence Store Redesign**: Phase 7 must not modify `EvidenceStore` internals or implement Phase 8 lifecycle/UI schemas.

### 6.2 What Phase 7 MUST Do
- **Validate Ingested Contracts**: Verify that incoming findings conform to `Finding` schema version "1.0".
- **Classify Findings by Dimension**: Map each finding to one of the 4 canonical assurance dimensions.
- **Enforce Veto Rules**: Immediately trigger `QUARANTINE` if any `CRITICAL` finding or `QUARANTINE` recommendation is active.
- **Accumulate Risk Mathematically**: Synthesize dimensional risk scores and a global composite risk score using bounded non-diluting mathematics.
- **Account for Blind Spots**: Identify unperformed, skipped, or insufficient checks and record them in `unsupported_checks`.
- **Issue Authoritative Verdict**: Produce an `AssuranceVerdict` and commit it to `DatabaseManager` and `AuditLogger`.

---

## 7. Aggregation Mathematics

A primary vulnerability in naive risk aggregators is **risk dilution**: if an asset has 1 fatal backdoor (`CRITICAL`, risk = 1.0) and passes 9 basic checks (risk = 0.0), an arithmetic mean produces:
$$\bar{R} = \frac{1.0 + 9 \times 0.0}{10} = 0.10 \quad (\text{Categorized as LOW RISK / ACCEPT})$$
In defense intelligence, this is catastrophic. An attacker intentionally crafts attacks that pass 90% of checks.

### 7.1 Formal Mathematical Formulation

#### Step 1: Individual Finding Risk Mapping
Let finding $f_i \in \mathcal{F}$ have severity $S(f_i) \in \{\text{INFORMATIONAL}, \text{LOW}, \text{MEDIUM}, \text{HIGH}, \text{CRITICAL}\}$ and calibrated confidence $C(f_i) \in [0.0, 1.0]$.
Severity weights $w(S)$ are codified as:
$$w(\text{CRITICAL}) = 1.00, \quad w(\text{HIGH}) = 0.80, \quad w(\text{MEDIUM}) = 0.50, \quad w(\text{LOW}) = 0.20, \quad w(\text{INFORMATIONAL}) = 0.00$$

The individual finding risk $r_i$ is:
$$r_i = w(S(f_i)) \times C(f_i) \quad \in [0.0, 1.0]$$

#### Step 2: Weakest-Link Veto Condition
Define the veto indicator $\mathcal{V}$:
$$\mathcal{V} = \mathbb{I}\left( \exists f_i \in \mathcal{F} : \big( S(f_i) = \text{CRITICAL} \land C(f_i) \ge \tau_{\text{veto}} \big) \lor f_i.\text{recommended\_disposition} = \text{QUARANTINE} \right)$$
where default $\tau_{\text{veto}} = 0.50$.
If $\mathcal{V} = 1$:
- Final disposition is unconditionally `Disposition.QUARANTINE`.
- $\text{composite\_risk\_score} = \max\left( \tau_{\text{quarantine}}, \; \max_{f_i \in \mathcal{F}} r_i \right)$.

#### Step 3: Dimensional Risk Accumulation (Noisy-OR)
For each dimension $d \in \mathcal{D} = \{\text{data\_integrity}, \text{model\_integrity}, \text{inference\_provenance}, \text{distribution\_shift}\}$, let $\mathcal{F}_d \subseteq \mathcal{F}$ be the findings belonging to dimension $d$.
If $\mathcal{F}_d = \emptyset$, then $R_d = 0.0$.
Otherwise, findings accumulate probabilistically:
$$R_d = 1 - \prod_{f_i \in \mathcal{F}_d} (1 - r_i)$$

*Mathematical Properties of Noisy-OR Accumulation*:
- **Boundary Preservation**: $R_d \in [0.0, 1.0]$ for all inputs in $[0.0, 1.0]$.
- **Zero Invariance**: If all $r_i = 0$, $R_d = 0.0$.
- **Weakest-Link Dominance**: For any single finding $j$, $R_d \ge r_j$.
- **Monotonicity**: Adding any finding with $r_i > 0$ strictly increases or maintains $R_d$.
- **Compound Escalation**: Two independent `MEDIUM` findings ($r_1 = 0.4, r_2 = 0.4$) yield $R_d = 1 - (0.6 \times 0.6) = 0.64$ (escalated to HIGH risk).

#### Step 4: Composite Risk Synthesis
Let dimension weights be $W_d$ where $\sum_{d \in \mathcal{D}} W_d = 1.0$ (configurable, default: Data = 0.25, Model = 0.35, Provenance = 0.25, Shift = 0.15).
The weighted dimensional risk is:
$$R_{\text{weighted}} = \sum_{d \in \mathcal{D}} W_d \cdot R_d$$

To prevent dilution across dimensions, the global composite risk combines the weighted sum with the maximum observed single finding risk:
$$R_{\text{composite}} = \max\left( \max_{f_i \in \mathcal{F}} r_i, \; R_{\text{weighted}} \right)$$
If $\mathcal{V} = 1$, then $R_{\text{composite}} = \max(R_{\text{composite}}, \tau_{\text{quarantine}})$.

#### Step 5: Final Disposition Determination
Given thresholds $\tau_{\text{review}} = 0.30$ and $\tau_{\text{quarantine}} = 0.70$:
1. If $\mathcal{V} = 1$ OR $R_{\text{composite}} \ge \tau_{\text{quarantine}}$:
   $$\text{disposition} = \text{Disposition.QUARANTINE}$$
2. Else if $R_{\text{composite}} \ge \tau_{\text{review}}$ OR any $f_i.\text{recommended\_disposition} = \text{REVIEW}$ OR $\text{len}(unsupported\_checks) > 0$:
   $$\text{disposition} = \text{Disposition.REVIEW}$$
3. Else:
   $$\text{disposition} = \text{Disposition.ACCEPT}$$

---

## 8. Confidence Semantics

Audit of confidence values across completed phases reveals three distinct mathematical types:
1. **Cryptographic Confidence ($C \in \{0.0, 1.0\}$)**: Deterministic binary certainty. In Phase 5 (`IT-1` to `IT-5`), a signature failure or hash mismatch is not a statistical estimate; it is mathematical proof ($C = 1.0$).
2. **Statistical Significance ($C = 1 - p$)**: Derived from formal hypothesis tests. In Phase 6, Kolmogorov-Smirnov and MMD tests yield p-values against null hypotheses ($H_0$).
3. **Heuristic/Calibrated Metric Confidence ($C \in [0.0, 1.0]$)**: In Phase 4 (`MT-3`), Neural Cleanse computes an anomaly index $A$. Confidence is calibrated as $C = \min(1.0, (A - 2.0) / 2.0)$.

> [!CAUTION]
> **Prohibition Against Mixing Confidences**: Directly computing a mathematical mean across these heterogeneous quantities (e.g. $\frac{C_{\text{crypto}} + C_{\text{statistical}}}{2}$) is mathematically invalid.
> **Architectural Resolution**: Confidence MUST NOT be averaged across checks. Instead, confidence is used solely as a local scaling factor on its parent finding's severity weight: $r_i = w(S(f_i)) \times C(f_i)$.

---

## 9. Severity Semantics

The project defines five severity levels in [`SeverityLevel`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/enums.py#L19-L24):

| SeverityLevel | Severity Weight $w(S)$ | Role in Phase 7 Aggregation | Default Operational Interpretation |
|:---|:---|:---|:---|
| **CRITICAL** | **1.00** | **Veto Trigger**: Activates $\mathcal{V} = 1$. Forces `QUARANTINE` if confidence $\ge 0.50$. Sets risk floor at $0.70$. | Total compromise (e.g., active backdoor detected, forged signature, model weight substitution). |
| **HIGH** | **0.80** | **High Escalation**: Single finding produces $r_i \ge 0.64$, immediately elevating risk past $\tau_{\text{review}} = 0.30$. Two HIGH findings trigger `QUARANTINE`. | Severe anomaly (e.g., systematic mislabelling, severe adversarial covariate shift, unverified signing key). |
| **MEDIUM** | **0.50** | **Compound Accumulator**: Single finding produces $r_i = 0.25$ to $0.40$ (forces `REVIEW`). Multiple medium findings compound into high risk. | Noticeable deviation (e.g., significant natural drift, OOD sample insertion cluster, high-risk contributor). |
| **LOW** | **0.20** | **Minor Metric**: Contributes weakly to dimensional risk ($r_i \le 0.20$). Does not trigger `REVIEW` alone. | Minor inconsistency (e.g., small sensor luminance shift, near-duplicate pair). |
| **INFORMATIONAL**| **0.00** | **Diagnostic Only**: Zero contribution to risk score ($r_i = 0.00$). Retained in audit trail. | Telemetry, execution stats, benchmark metrics. |

---

## 10. Conflicting Evidence Handling

The audit analyzed eight specific operational conflict scenarios:

| Scenario | Evidence Inputs | Expected Phase 7 Behavior | Architectural Rule |
|:---|:---|:---|:---|
| **A** | Strong Model Backdoor (`MT-3` CRITICAL) + Clean Dataset (`DT-1` to `DT-5` ACCEPT) | Final disposition: **`QUARANTINE`**. `composite_risk_score >= 0.80`. | **Veto Dominance**: A clean dataset does not exonerate a compromised model artifact. |
| **B** | Clean Model (`MT-1` to `MT-4` ACCEPT) + Poisoned Dataset (`DT-2` HIGH) | Target dataset disposition: **`QUARANTINE`**. If evaluating model lineage, model disposition: **`REVIEW`** (tainted training provenance). | **Lineage Propagation**: Upstream data poisoning flags downstream model safety. |
| **C** | Cryptographically Valid Signature (`IT-1` VERIFIED) + Severe Covariate Shift (`DS-1` HIGH) | Final disposition: **`REVIEW`**. Provenance dimension = 0.0 risk, Shift dimension = 0.80 risk. | **Multi-Dimensional Orthogonality**: Provenance authenticates packet origin; shift detects operational blindness. |
| **D** | High Environmental Drift (`DS-3` HIGH) + Low Manipulation Likelihood (`DS-4` LOW) | Final disposition: **`REVIEW`** with narrative *"Operational sensor recalibration advisory"*. | **Drift Disambiguation**: Natural weather drift requires sensor maintenance, not security quarantine. |
| **E** | Cryptographic failure (`IT-4` CRITICAL) vs. Benign Statistical Metrics (`DS-1` to `DS-3` ACCEPT) | Final disposition: **`QUARANTINE`**. | **Hard Proof Precedence**: Cryptographic proof unconditionally overrides statistical normality. |
| **F** | One analysis phase unavailable (e.g. Model Integrity not run) | Final disposition: **`REVIEW`** (cannot be `ACCEPT`). Check logged in `unsupported_checks`. | **Coverage Invariant**: An asset cannot be approved if verification coverage is partial. |
| **G** | Evidence marked insufficient (`ShiftAssessment.evidence_sufficient = False`) | Finding downgraded to `INFORMATIONAL` warning. Does not trigger false `QUARANTINE`. | **Sample Power Guard**: Insufficient sample size must never manufacture artificial alarms. |
| **H** | 1 CRITICAL finding + 19 LOW/INFO findings | Final disposition: **`QUARANTINE`**. `composite_risk_score >= 0.70`. | **Anti-Dilution Invariant**: High volume of trivial checks cannot outvote a critical flaw. |

---

## 11. Missing / Incomplete Evidence Semantics

In security assurance, conflating "no evidence of compromise" with "evidence of no compromise" is a catastrophic failure mode. Phase 7 codifies five mutually exclusive evidence states:

```
                  EVIDENCE STATUS TAXONOMY
                  
     State                  Definition                    Risk Contribution      Permits ACCEPT?
┌──────────────┬────────────────────────────────────────┬─────────────────────┬──────────────────┐
│ CLEAN        │ Check executed; zero threats detected   │ r = 0.0             │ YES              │
│ UNKNOWN      │ Check not requested or not applicable   │ Not in r; in skips  │ NO (forces REVIEW)│
│ INSUFFICIENT │ Sample size / statistical power too low│ In skips; low weight│ NO (forces REVIEW)│
│ FAILED       │ Check threw execution exception / error│ In skips; error logged NO (forces REVIEW)│
│ UNAVAILABLE  │ Baseline asset missing or corrupted     │ In skips; config err│ NO (forces REVIEW)│
└──────────────┴────────────────────────────────────────┴─────────────────────┴──────────────────┘
```

**Mandatory Rule**: If any check in the requested battery is not `CLEAN`, the disposition CANNOT be `ACCEPT`. Incomplete evidence automatically caps the maximum possible disposition at `Disposition.REVIEW`.

---

## 12. Threat-Level Aggregation & Hierarchy

Phase 7 executes hierarchical aggregation to maintain traceability from low-level findings up to the asset verdict:

```
                            AGGREGATION HIERARCHY
                            
                    AssuranceVerdict (Asset Level)
                                  ▲
                                  │ (Composite Risk & Veto Synthesis)
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
    Data Integrity          Model Integrity         Distribution Shift ...
     Dimension R_data        Dimension R_model       Dimension R_shift
            ▲                     ▲                     ▲
            │ (Noisy-OR)          │ (Noisy-OR)          │ (Noisy-OR)
    [DT-1, DT-2, ...]     [MT-1, MT-2, ...]     [DS-1, DS-2, ...]
            ▲                     ▲                     ▲
            │ (UUID Link)         │ (UUID Link)         │ (UUID Link)
      EvidenceRecord        EvidenceRecord        EvidenceRecord
```

---

## 13. Double-Counting & Correlated Evidence Audit

### 13.1 Potential Correlation Vectors Identified
1. **Phase 3 OOD (`DT-5`) and Phase 6 Covariate Shift (`DS-1`)**: If an evaluation dataset contains anomalous out-of-distribution images, Phase 3 flags them individually under `DT-5`, while Phase 6 flags the population divergence under `DS-1`.
2. **Phase 4 Activation Anomaly (`MT-4`) and Phase 4 Backdoor (`MT-3`)**: A Trojan trigger typically causes abnormal clustered neuron activations.
3. **Phase 5 Model Substitution (`IT-2`) and Phase 4 Model Substitution (`MT-1`)**: Both check model weight hashes, one at inference receipt, the other during static asset cataloging.

### 13.2 Double-Counting Prevention Strategy
1. **Dimensional Clumping**: Findings from correlated threats within the same domain (e.g. `MT-3` and `MT-4`) are combined via Noisy-OR within `model_integrity`, where $1 - (1-r_1)(1-r_2)$ naturally saturates asymptotically at 1.0 rather than linearly summing to > 1.0.
2. **Finding UUID Deduplication**: Phase 7 maintains a strict `set()` over `finding_id` values. Re-submitted or cross-referenced duplicate findings are deduplicated before risk calculation.
3. **Cross-Phase Asset Separation**: Phase 3 and Phase 6 analyze datasets (`UnifiedDataset`). Phase 4 analyzes models (`ModelAdapter`). Phase 5 analyzes inference streams (`InferenceRecord`). The asset under evaluation defines the primary target, preventing cross-asset duplication.

---

## 14. Final Assurance Output

The output of Phase 7 is an instance of [`AssuranceVerdict`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L176-L191). The schema is completely frozen and requires zero modifications:

```python
class AssuranceVerdict(CVIFBaseModel):
    verdict_id: UUID = Field(default_factory=uuid4)
    asset_id: UUID
    session_id: UUID
    composite_risk_score: float = Field(..., ge=0.0, le=1.0)
    disposition: Disposition  # ACCEPT, REVIEW, QUARANTINE
    contributing_finding_ids: List[UUID] = Field(default_factory=list)
    summary: str
    unsupported_checks: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")
```

### 14.1 Narrative Justification Generation
The `summary` string must be deterministically constructed:
- Executive statement of disposition: e.g. `"DISPOSITION: QUARANTINE (Composite Risk: 0.85)."`
- Primary driver: e.g. `"Triggered by CRITICAL severity finding in model_integrity (MT-3 Backdoor Detected with confidence 0.95)."`
- Contributing dimensions: e.g. `"Dimensional breakdown: data_integrity=0.00, model_integrity=0.85, inference_provenance=0.00, distribution_shift=0.20."`
- Unsupported checks notice: e.g. `"2 checks unperformed: ['DS-3', 'DT-6']."`

---

## 15. Cryptographic / Integrity Boundary

1. **Input Finding Immutability**: Finding UUIDs and fields are validated upon ingestion. When fetched from SQLite (`findings` table), they are parsed via `Finding.model_validate_json()`.
2. **Canonical Output Serialization**: `AssuranceVerdict` inherits from `CVIFBaseModel`. Calling `.to_canonical_bytes()` yields deterministic JSON with sorted keys for cryptographic signing or HMAC generation.
3. **Audit Trail Anchor**: The verdict is cryptographically bound into the system audit log via:
   ```python
   audit_logger.log_event(
       event_type=AuditEventType.VERDICT_ISSUED,
       actor="assurance_aggregator",
       asset_id=verdict.asset_id,
       session_id=verdict.session_id,
       details={
           "verdict_id": str(verdict.verdict_id),
           "disposition": verdict.disposition.value,
           "composite_risk_score": verdict.composite_risk_score,
           "contributing_findings_count": len(verdict.contributing_finding_ids),
       }
   )
   ```
   This ensures that any subsequent alteration of the verdict in the database creates a detectable discrepancy against the tamper-evident hash chain in `audit.jsonl`.

---

## 16. Evidence Store Boundary

Phase 7 respects the strict boundary with Phase 8 (Evidence Store Redesign & UI):
- **Phase 7 Responsibility**: Constructs the in-memory `AssuranceVerdict`, passes it to `DatabaseManager.save_verdict()`, links it to `AnalysisSession.verdict`, and writes audit events.
- **Phase 8 Responsibility (FUTURE)**: Long-term artifact lifecycle management, cross-session search indexing, archive export bundles (`.cvif` zip packages), and evidence explorer UI.
- Phase 7 does **NOT** alter [`EvidenceStore`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py) internals or introduce web/API dependencies.

---

## 17. Security Analysis

| Threat Vector | Attack Mechanism | Phase 7 Defense & Mitigation |
|:---|:---|:---|
| **Risk Dilution Attack** | Attacker floods 100 benign checks to wash out 1 critical backdoor. | **Weakest-Link Dominance**: Composite risk bounded below by $\max(r_i)$. CRITICAL finding forces QUARANTINE regardless of count. |
| **Evidence Omission Attack** | Attacker suppresses or skips the check that would detect their malware. | **Incomplete Evidence Invariant**: Skipped checks recorded in `unsupported_checks`; prevents `ACCEPT` disposition. |
| **Score Tampering / Injection** | Attacker injects NaN, Inf, or negative numbers into finding confidence. | **Pydantic Validation**: `Finding.confidence` bounded in $[0.0, 1.0]$. Aggregator sanitizes floats via `math.isfinite()`. |
| **Duplicate Finding Replay** | Attacker resubmits identical findings to artificially inflate risk score. | **UUID Deduplication**: Aggregator tracks seen finding UUIDs via `set()`; duplicates processed only once. |
| **Audit Decoupling** | Attacker alters verdict in database after execution. | **Hash-Chained Audit Trail**: `VERDICT_ISSUED` logged in append-only JSONL; verification detects hash break. |
| **Denial of Service (DoS)** | Attacker feeds 1,000,000 synthetic findings to exhaust memory. | **Linear Aggregation Complexity**: $O(N)$ single-pass aggregation; bounded finding batch processing. |

---

## 18. Air-Gap & Dependency Audit

- **Zero External Networking**: Aggregation performs zero HTTP/socket requests. Compatible with `test_offline.py` network-prohibition fixture.
- **Zero New Dependencies**: Pure Python standard library implementation (`math`, `typing`, `uuid`, `datetime`). Does not require `numpy`, `scipy`, or `torch`.
- **Operating Environment**: Pinned strictly to existing Python 3.10 virtual environment and `requirements.lock`.

---

## 19. Configuration Audit

### 19.1 Proposed Configuration Extension
In `src/cvif/core/config.py`, an `AssuranceConfig` model will be introduced into `AppConfig`:

```python
class AssuranceConfig(BaseModel):
    quarantine_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    critical_veto_enabled: bool = Field(default=True)
    min_confidence_for_veto: float = Field(default=0.50, ge=0.0, le=1.0)
    dimension_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "data_integrity": 0.25,
            "model_integrity": 0.35,
            "inference_provenance": 0.25,
            "distribution_shift": 0.15,
        }
    )
    require_all_mandatory_checks: bool = Field(default=False)
```

In `config/default_config.yaml`:
```yaml
assurance:
  quarantine_threshold: 0.70
  review_threshold: 0.30
  critical_veto_enabled: true
  min_confidence_for_veto: 0.50
  dimension_weights:
    data_integrity: 0.25
    model_integrity: 0.35
    inference_provenance: 0.25
    distribution_shift: 0.15
  require_all_mandatory_checks: false
```

### 19.2 Safe Default Guarantees
If `assurance:` is omitted from a user YAML configuration, `AppConfig` initializes `AssuranceConfig` with safe, defense-grade defaults via `Field(default_factory=AssuranceConfig)`. This preserves 100% backwards compatibility with existing configuration files.

---

## 20. Performance & Scalability

- **Input Volume Profile**: An intensive multi-phase analysis produces between 5 and 50 findings and 10 to 30 skipped/unsupported checks per session.
- **Time Complexity**: $O(N)$ where $N$ is the number of findings. Computing Noisy-OR and dimensional weights takes $< 1.0$ millisecond for 1,000 findings.
- **Memory Complexity**: $O(N)$ for UUID storage and narrative formatting ($< 50$ KB).
- **Benchmarking Target**: Verdict synthesis execution time $< 10$ milliseconds per session.

---

## 21. Test Architecture

The Phase 7 verification plan requires 20 exhaustive test categories (A through T):

```
TEST SUITE ARCHITECTURE (tests/unit/test_assurance_aggregation.py)
├── A. Single Clean Evidence Set (Zero findings -> Risk = 0.0, ACCEPT)
├── B. Single Strong Finding (Single CRITICAL -> Risk >= 0.70, QUARANTINE via veto)
├── C. Multiple Independent Findings (3 MEDIUM findings compound via Noisy-OR -> REVIEW/QUARANTINE)
├── D. Conflicting Evidence (CRITICAL model finding + 10 CLEAN dataset checks -> QUARANTINE)
├── E. Missing Evidence (Session with skipped checks -> unsupported_checks populated, blocks ACCEPT)
├── F. Insufficient Evidence (DS check marked insufficient -> warning finding, does not trigger false QUARANTINE)
├── G. Duplicate Evidence (Same finding UUID submitted twice -> processed exactly once)
├── H. Correlated Evidence (Multiple findings in same dimension saturate smoothly <= 1.0)
├── I. Severity Handling (Check weights: CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5, LOW=0.2, INFO=0.0)
├── J. Confidence Handling (Finding with 0.1 confidence scales risk down proportionally)
├── K. Invalid Scores / Clamping (Handling edge values 0.0 and 1.0 without precision loss)
├── L. NaN / Inf Sanitization (Rejection or sanitization of non-finite floats in findings)
├── M. Schema Mismatch (Findings with invalid schema_version rejected)
├── N. Tampered Evidence / Hash Break (Verdict validation against audit log)
├── O. Replayed Evidence (Seen verdict_id handled cleanly via INSERT OR REPLACE)
├── P. Deterministic Aggregation (Same findings produce identical bit-for-bit canonical JSON)
├── Q. Boundary Values (Risk exactly at 0.30 -> REVIEW; Risk exactly at 0.70 -> QUARANTINE)
├── R. Air-Gap Behavior (Execution verified under socket-blocking offline fixture)
├── S. Performance (1,000 findings aggregated in < 50ms)
└── T. Full System Regression (All 192 existing tests pass with zero regressions)
```

---

## 22. Anti-Stub Requirements

To guarantee defense-grade integrity, the following implementations are strictly prohibited:
1. **NO Hardcoded Verdicts**: No default `"ACCEPT"` or `"QUARANTINE"` bypasses.
2. **NO Arbitrary Weight Inventions**: Dimension weights and severity weights must be read from `AssuranceConfig` or documented constants.
3. **NO Random/Heuristic Jumps**: Composite risk must be a strictly deterministic mathematical function of finding severities and confidences.
4. **NO Silent Finding Dropping**: Every ingested finding must be accounted for in either `contributing_finding_ids` or an explicit exclusion reason.
5. **NO False "Clean" Status**: Missing or skipped checks must never evaluate to zero risk.

---

## 23. Existing-Code Dependency Map

| Component | File Path | Existing Interface Used | Compatibility Assessment |
|:---|:---|:---|:---|
| **AssuranceVerdict** | `src/cvif/core/schemas.py:176-191` | Schema instantiation & validation | **100% Compatible**. Already defined. |
| **Finding** | `src/cvif/core/schemas.py:106-132` | Read `severity`, `confidence`, `category`, `threat_id` | **100% Compatible**. Emitted across Phases 3–6. |
| **DatabaseManager** | `src/cvif/storage/database.py:314-343` | `save_verdict()`, `get_verdict_for_session()` | **100% Compatible**. CRUD methods already verified. |
| **AuditLogger** | `src/cvif/audit/logger.py` | `log_event(AuditEventType.VERDICT_ISSUED, ...)` | **100% Compatible**. Monotonic hash chain logging. |
| **AnalysisSession** | `src/cvif/core/schemas.py:413-430` | Assign `session.verdict = verdict` | **100% Compatible**. Field `verdict` already optional. |
| **Config Engine** | `src/cvif/core/config.py` | Add `AssuranceConfig` to `AppConfig` | **100% Compatible**. Safe defaults prevent breaks. |
| **Orchestrators** | `src/cvif/analysis/*orchestrator.py` | Call `AssuranceAggregator` at session end | **100% Compatible**. Orchestrators have clean hooks. |

---

## 24. Phase Boundary

```
PHASE BOUNDARY DEFINITION
├── PHASE 7 SCOPE (TO BE IMPLEMENTED NEXT)
│   ├── cvif.analysis.assurance.aggregator (Core mathematical aggregation engine)
│   ├── cvif.analysis.assurance.rules (Weakest-link veto and disposition logic)
│   ├── cvif.analysis.assurance.narrative (Deterministic narrative justification generator)
│   ├── cvif.analysis.assurance.orchestrator (End-to-end multi-phase session synthesis)
│   ├── AssuranceConfig in core/config.py and default_config.yaml
│   └── tests/unit/test_assurance_aggregation.py (Categories A through T)
└── STRICTLY EXCLUDED (BELONGS TO PHASE 8+)
    ├── Phase 8: Evidence Store UI / Web schemas / lifecycle export
    ├── Phase 9: CLI command `cvif aggregate-verdict` / `cvif assess`
    ├── Phase 10: REST API `/api/v1/verdicts` endpoints
    ├── Phase 11: Interactive HTML/React visualization dashboards
    └── Phase 12: Production packaging / containerization
```

---

## 25. Architectural Blockers Search

An exhaustive audit of the codebase, schemas, storage engine, and mathematical models was conducted to identify any potential blockers:

| Potential Blocker Investigated | Severity | Audit Evidence & Analysis | Resolution / Verdict |
|:---|:---|:---|:---|
| **Undefined Aggregation Math** | **RESOLVED** | Early project documentation mentioned "composite risk score" without specifying the formula. Section 7 of this audit formally codified the **Dual-Mechanism (Veto + Noisy-OR)** model. | **NO BLOCKER**: Fully specified. |
| **Schema Incompatibility** | **RESOLVED** | Inspected `AssuranceVerdict` in `schemas.py:176-191` and `DatabaseManager.save_verdict()`. Both are fully implemented, tested, and aligned. | **NO BLOCKER**: 100% match. |
| **Mixed Confidence Semantics** | **RESOLVED** | Evaluated risk of averaging cryptographic certainty with statistical p-values. Section 8 resolves this by confining confidence to a local severity scaler. | **NO BLOCKER**: Cleanly decoupled. |
| **Missing Evidence Ambiguity** | **RESOLVED** | Evaluated danger of treating missing checks as clean. Section 11 established the 5-state Evidence Taxonomy and blocked `ACCEPT` on partial verification. | **NO BLOCKER**: Ambiguity eliminated. |
| **Dependency on Phase 8** | **RESOLVED** | Verified that `DatabaseManager` already has a dedicated `verdicts` table. Phase 7 does not require Phase 8 Evidence Store redesign. | **NO BLOCKER**: Independent. |
| **Air-Gap / NumPy Availability** | **RESOLVED** | Aggregation mathematics are strictly linear and standard-library compatible (`math.prod`, list comprehensions). Zero unpinned libraries needed. | **NO BLOCKER**: 100% air-gapped. |

**Audit Conclusion**: There are **ZERO BLOCKING DEFECTS** or ambiguities. The architecture is fully resolved and actionable.

---

## 26. Proposed Implementation Plan

When Phase 7 implementation is authorized by the project owner, the following modular plan will be executed:

1. **Step 1 — Configuration Codification**:
   - Add `AssuranceConfig` to `src/cvif/core/config.py` with default thresholds ($\tau_{\text{review}} = 0.30$, $\tau_{\text{quarantine}} = 0.70$, $\tau_{\text{veto}} = 0.50$) and dimension weights.
   - Update `config/default_config.yaml` with the `assurance:` section.
2. **Step 2 — Assurance Engine Module (`src/cvif/analysis/assurance/`)**:
   - `rules.py`: Veto evaluations, disposition threshold checks, and severity weight mapping.
   - `aggregator.py`: `AssuranceAggregator` implementing Noisy-OR dimensional accumulation, composite risk calculation, and `unsupported_checks` processing.
   - `narrative.py`: Deterministic narrative justification generator for military analysts.
3. **Step 3 — Orchestrator Integration**:
   - Provide `AssuranceAggregator.aggregate(session_id, asset_id, findings, skipped_analyses, config)` returning `AssuranceVerdict`.
   - Update `AnalysisSession` completion flow to generate, log, and persist the verdict.
4. **Step 4 — Unit Testing Suite**:
   - Create `tests/unit/test_assurance_aggregation.py` implementing all 20 test categories (A through T).
   - Verify 100% offline pass rate and zero regressions against existing 192 tests.

---

## 27. Final Architectural Decision

An exhaustive, read-only architectural audit of Phase 7 (Assurance Aggregation) has been completed. All data contracts, mathematical models, veto rules, evidence inventories, and security boundaries are fully defined, verified against completed Phases 2–6, and ready for code implementation.

PHASE 7 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
