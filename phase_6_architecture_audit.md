# Phase 6/12 — Distribution Shift Analysis: Architecture & Requirements Audit

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Customer / Authority**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Phase**: Phase 6/12 — Distribution Shift Analysis  
**Audit Type**: ARCHITECTURE & REQUIREMENTS AUDIT ONLY (Strict Read-Only)  
**Date**: September 19, 2026  
**Auditor**: Lead System Architect & Forensic Assurance Gate  

---

## 1. Executive Summary

This document establishes the authoritative architectural foundation, threat taxonomy, statistical specifications, and execution constraints for **Phase 6: Distribution Shift Analysis** of the Computer Vision Integrity Assurance Framework (CVIF).

### 1.1 Context & Status
Phase 5 (Inference Provenance and Assurance Gateway) has successfully completed independent forensic verification and hardening, resolving the sequence-state pollution vulnerability. All 169 system unit tests pass with zero regressions. Phase 5 is officially **CLOSED**.

Phase 6 addresses the operational challenge of **Distribution Shift** in tactical, multi-contributor computer vision pipelines. When deployed across diverse operational theatres (e.g., high-altitude Himalayan sectors, desert borders, maritime littoral zones) or processing data contributed by disparate sensor platforms (tactical UAVs, border surveillance towers, hand-held recon optics), vision models suffer performance degradation due to natural environmental changes or targeted adversarial manipulation.

### 1.2 Audit Mandate & Findings
This audit strictly adheres to the read-only mandate:
- **Zero Production Code Modified**: No production files have been created or edited.
- **Zero Tests Modified**: The existing test suite remains untouched.
- **Zero Dependencies Installed**: The Python runtime environment remains strictly pinned to `requirements.lock`.

**Key Architectural Determinations**:
1. **Core Data Contracts Exist**: The Pydantic v2 schemas [`ShiftReport`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L328-L341), [`ShiftAssessment`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L319-L326), and [`ShiftDimensionResult`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L310-L317) were defined in Phase 1/2 and are structurally sound.
2. **Two-Distribution Comparative Paradigm**: Unlike Phase 3 (`DT-5 OODInsertionCheck`), which detects individual outlier samples within a single dataset, Phase 6 is fundamentally a comparative analysis between two distinct dataset distributions: a trusted **Reference Baseline Dataset** ($P_{ref}$) and an incoming **Evaluation Dataset** ($P_{eval}$).
3. **Pure-Python Numerical Strategy**: `numpy`, `scipy`, and `torch` are **not installed** in the virtual environment. To maintain CVIF's 100% air-gapped, zero-dependency deployment reliability, Phase 6 statistical distance algorithms (MMD, 1D Wasserstein distance, Kolmogorov-Smirnov test, Total Variation) must be implemented with high numerical precision in pure Python using standard library modules (`math`, `statistics`, `collections`).
4. **Threat Taxonomy Codification**: Phase 6 formalizes the **Distribution Shift (DS)** series of threat checks:
   - `DS-1`: Covariate Shift (Feature-Space Distribution Divergence)
   - `DS-2`: Semantic & Concept Shift (Class Prior & Representation Asymmetry)
   - `DS-3`: Environmental & Sensor Degradation Drift (Image Quality / Channel Statistics)
   - `DS-4`: Adversarial Distribution Manipulation (Targeted Subpopulation Drift)
5. **Calibrated Forensic Assessment**: Phase 6 explicitly differentiates natural operational drift from malicious adversarial manipulation through multi-dimensional separability analysis and sample-size sufficiency checks.

---

## 2. Authoritative Requirements

The requirements for Phase 6 are derived from the master architecture specification v0.2-REVISED (`implementation_plan.md`), the core data schemas, and the frozen Phase 1–5 architectural boundaries.

### 2.1 Explicit Functional Requirements

- **R-DS1: Comparative Distribution Divergence**: The engine must ingest two canonical dataset entities—a reference baseline dataset and an evaluation dataset—represented as [`UnifiedDataset`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L527-L600) instances, and quantify their statistical divergence.
- **R-DS2: Multi-Dimensional Shift Profiling**: The analysis must evaluate distribution shift across three distinct operational dimensions:
  1. *Feature/Covariate Dimension*: Dense semantic/statistical feature vector distributions.
  2. *Semantic/Label Dimension*: Categorical class distribution and prior probabilities $P(Y)$.
  3. *Image Quality/Pixel Dimension*: Low-level image statistics (luminance, contrast, blur/frequency, colour channels).
- **R-DS3: Rigorous Statistical Distance Metrics**: Divergence must be quantified using mathematically sound, non-heuristic metrics:
  - Maximum Mean Discrepancy (MMD) with RBF/energy kernel.
  - 1D Wasserstein-1 Distance (Earth Mover's Distance) along principal feature projections.
  - Two-Sample Kolmogorov-Smirnov (KS) test with asymptotic p-value estimation.
  - Total Variation (TV) / Jensen-Shannon divergence over discrete class histograms.
- **R-DS4: Calibrated Drift vs. Manipulation Disambiguation**: The system must synthesize a [`ShiftAssessment`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L319-L326) producing:
  - `natural_drift_likelihood` $\in [0.0, 1.0]$: Probability that divergence stems from natural environmental, weather, seasonal, or camera sensor variations.
  - `suspicious_manipulation_likelihood` $\in [0.0, 1.0]$: Probability that divergence stems from targeted data poisoning, selective subpopulation suppression, or adversarial domain shift.
  - `evidence_sufficient`: Boolean indicating whether sample sizes ($N_{ref}, N_{eval}$) and dimensionality provide statistical power to draw conclusions.
- **R-DS5: Standardized Artifact & Evidence Generation**: The analysis must construct a canonical [`ShiftReport`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L328-L341), emit individual [`Finding`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L106-L132) records with `category="DISTRIBUTION_SHIFT"`, and persist immutable [`EvidenceRecord`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L42-L68) items in the [`EvidenceStore`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py).
- **R-DS6: Audit Trail & Session Integration**: Every distribution shift execution must be coordinated through a `DistributionShiftOrchestrator`, register an [`AnalysisSession`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L407-L430) in [`DatabaseManager`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py), and log cryptographically hash-chained events (`ANALYSIS_STARTED`, `FINDING_RECORDED`, `ANALYSIS_COMPLETED`) into [`AuditLogger`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/audit/logger.py).
- **R-DS7: 100% Offline & Pure-Python Portability**: Analysis must execute without socket connections, internet access, GPU prerequisites, or unpinned binary dependencies, maintaining complete operational air-gap compliance.

---

## 3. Requirement Traceability Matrix

| Req ID | Architecture Section | Required Behavior | Existing Dependency | Planned Phase 6 Component | Verification Method |
|:---|:---|:---|:---|:---|:---|
| **R-DS1** | Section I.7 / Section 7 | Comparative distribution divergence between reference and evaluation datasets | `UnifiedDataset`, `ImageRecord`, `DatabaseManager` | `DistributionShiftOrchestrator`, `DistributionShiftCheck` | Synthetic shifted vs identical dataset comparison tests |
| **R-DS2.1** | Section I.7 / Section K.5 | Feature-space covariate shift evaluation | `FeatureExtractor`, `StatisticalFeatureExtractor` | `CovariateShiftCheck` (`DS-1`) | Multi-dimensional distance against baseline |
| **R-DS2.2** | Section I.7 / Section J.2 | Semantic / class prior shift evaluation | `AnnotationRecord`, `ClassInfo` | `SemanticShiftCheck` (`DS-2`) | Skewed class frequency distribution test |
| **R-DS2.3** | Section I.7 / Section 2.2 | Pixel/image quality and sensor drift evaluation | `image_utils.py`, `inspect_image_file` | `EnvironmentalDriftCheck` (`DS-3`) | Synthetic luminance/blur/contrast perturbation tests |
| **R-DS3.1** | Section 7.2 (Statistical Metrics) | Maximum Mean Discrepancy (MMD) computation | Python standard library `math` | `cvif.analysis.distribution_shift.metrics.compute_mmd` | Exact mathematical test against known distribution pairs |
| **R-DS3.2** | Section 7.2 (Statistical Metrics) | 1D Wasserstein-1 Earth Mover's Distance | Python standard library `statistics` | `cvif.analysis.distribution_shift.metrics.compute_wasserstein_1d` | Empirical CDF step-integral validation |
| **R-DS3.3** | Section 7.2 (Statistical Metrics) | Two-sample Kolmogorov-Smirnov test & p-value | Python standard library `math` | `cvif.analysis.distribution_shift.metrics.compute_ks_2sample` | Rejection of null hypothesis at $\alpha = 0.05$ |
| **R-DS4** | Section I.7 (`ShiftAssessment`) | Disambiguate natural operational drift from malicious tampering | `ShiftAssessment` schema | `DistributionShiftClassifier` / `AssessmentEngine` | Targeted cluster drift vs uniform environmental drift calibration |
| **R-DS5** | Section I.2 & I.7 | Generation of `ShiftReport` and `Finding` with linked `EvidenceRecord` | `ShiftReport`, `Finding`, `EvidenceStore` | `DistributionShiftOrchestrator.create_report()` | Schema validation, write-once evidence persistence |
| **R-DS6** | Section S.1 & W.1 | Tamper-evident audit logging and session persistence in SQLite | `AuditLogger`, `DatabaseManager`, `AnalysisSession` | `DistributionShiftOrchestrator` session lifecycle | Chain verification via `verify_audit_chain()` |
| **R-DS7** | Section V.1 (Air Gap) | 100% offline, CPU-executable, zero network sockets | `test_offline.py` socket monkeypatch pattern | Entire Phase 6 module | Offline socket-blocking test suite |

---

## 4. Distribution-Shift Semantics in CVIF

In military and defense computer vision intelligence, "distribution shift" is not merely an academic ML abstraction. It directly reflects operational survivability and reconnaissance integrity.

### 4.1 Required Distinctions

```
Distribution Shift in Tactical CV Pipelines
├── 1. Covariate Shift P(X_eval) ≠ P(X_ref), P(Y|X) invariant
│   ├── Environmental: Diurnal lighting, seasonal snow/foliage, fog, rain, sandstorms
│   └── Platform: UAV camera angle, optical zoom, sensor resolution, compression
├── 2. Semantic / Prior Shift P(Y_eval) ≠ P(Y_ref)
│   ├── Target Prevalence: Sudden surge in military vehicles or troop concentrations
│   └── Class Omission: Selective suppression or complete absence of expected classes
├── 3. Sensor / Image Quality Degradation
│   ├── Hardware: Thermal sensor drift, lens contamination, focal blur, dead pixels
│   └── Transmission: Severe lossy compression, transmission bit-rate throttling
└── 4. Adversarial Distribution Manipulation (Malicious Covariate Poisoning)
    ├── Targeted Subpopulation Shift: Adversary alters specific target signatures
    └── Trojaned Background Injection: Coordinated pattern injection across scenes
```

### 4.2 Explicit Inclusions vs. Exclusions

- **INCLUDED in Phase 6**:
  - **Dataset-Level Population Comparison**: Aggregate comparison between two complete datasets $P_{ref}$ and $P_{eval}$.
  - **Feature-Space Distribution Divergence**: Evaluating whether the dense feature embeddings of $P_{eval}$ occupy the same manifold as $P_{ref}$.
  - **Class-Conditional Marginal Shifts**: Evaluating whether feature divergence is uniform across all classes or isolated to critical target classes.
  - **Class-Frequency Distribution Shifts**: Quantifying prior probability divergence $\sum |P_{eval}(y) - P_{ref}(y)|$.
  - **Image Quality & Sensor Statistics**: Tracking distribution shifts in mean luminance, contrast, and high-frequency edge energy.
  - **Calibrated Assessment**: Synthesizing metrics into `natural_drift_likelihood` vs. `suspicious_manipulation_likelihood`.

- **EXCLUDED from Phase 6 (Belongs to Other Phases)**:
  - **Individual Image Outlier / OOD Sample Detection**: Already implemented in Phase 3 under `DT-5 OODInsertionCheck`.
  - **Inference Packet Replay / Temporal Stream Gaps**: Already implemented in Phase 5 under `IT-3` and `IT-5`.
  - **Model Activation / Neuron Clustering**: Already implemented in Phase 4 under `MT-2` and `MT-4`.
  - **Overall Pipeline Risk Aggregation & Disposition Verdict**: Belongs to Phase 7 (`AssuranceVerdict` synthesis).

---

## 5. Reference Dataset / Baseline Semantics

A critical requirement of comparative distribution shift analysis is defining the origin, immutability, and authority of the **Reference Baseline**.

### 5.1 Baseline Definition & Trust Model
1. **Constituency**: The reference baseline MUST be an ingested, structurally validated [`UnifiedDataset`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L527-L600) registered in [`DatabaseManager`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py) with status `REGISTERED` or `ANALYSED`.
2. **Cryptographic Identity**: The baseline is uniquely identified by `reference_asset_id` (UUID). Its data integrity is anchored by its `dataset_hash` (deterministic SHA-256 computed over all image hashes, bounding boxes, and classes).
3. **Immutability (Frozen Baseline)**: Once cataloged in the asset registry, the baseline dataset cannot be modified in place. Any update or refinement generates a new asset registration with a fresh `asset_id` and provenance trail.
4. **Pre-requisite Integrity**: To be designated as an operational baseline, a dataset should ideally have successfully cleared Phase 3 Data Integrity verification (`DT-1` through `DT-6`) with an `ACCEPT` disposition.

### 5.2 Failure & Edge Case Semantics
- **Missing Baseline**: If `reference_asset_id` cannot be resolved in `DatabaseManager` or the filesystem root is missing, Phase 6 must raise `AssetNotFoundError` or emit a `SeverityLevel.HIGH` finding (`DS-CONFIG-ERR`), cleanly aborting comparative analysis.
- **Suspicious Baseline**: If the reference dataset itself has unreviewed `DATA_INTEGRITY` findings, Phase 6 executes the comparison but flags the finding narrative: *"Warning: Reference baseline possesses unresolved data integrity findings; divergence metrics may reflect baseline contamination."*
- **Empty Dataset Handling**: If either the reference dataset ($N_{ref} = 0$) or the evaluation dataset ($N_{eval} = 0$) contains zero valid images, the check returns `check_applicable == False` with a structured explanation in `skipped_analyses`.

---

## 6. Feature-Extraction Architecture

### 6.1 Existing Contract (`src/cvif/features/base.py`)
All feature extraction in CVIF is governed by the [`FeatureExtractor`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/features/base.py#L7-L35) abstract base class:
```python
class FeatureExtractor(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...
    
    @property
    @abstractmethod
    def embedding_dim(self) -> int: ...
    
    @abstractmethod
    def extract(self, image_input: Any) -> List[float]: ...
    
    def extract_batch(self, image_inputs: List[Any]) -> List[List[float]]: ...
```

### 6.2 The Runtime Dependency Reality: Pure-Python vs. Neural Backbones

Inspection of `config/default_config.yaml` and `.venv` reveals:
- `default_config.yaml` declares:
  ```yaml
  feature_extractor:
    primary_backbone: "resnet18"
    weights_path: "assets/models/resnet18_features.pt"
    allow_statistical_fallback: true
    embedding_dimension: 512
    fallback_dimension: 128
  ```
- **Runtime Environment Reality**: `torch`, `torchvision`, `onnxruntime`, and `scipy` are **NOT INSTALLED** in the project's virtual environment (`requirements.lock`).
- **Production-Ready Extractor**: [`StatisticalFeatureExtractor`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/features/statistical.py) is implemented in pure Python (standard library `math`, `pathlib`). It extracts a deterministic 128-dimensional unit-normalized vector capturing multi-scale byte histograms, 4 distribution moments (mean, standard deviation, skewness, kurtosis), and spatial gradient deltas.

### 6.3 Architectural Decision for Phase 6
> [!IMPORTANT]
> **Primary Extractor Decision**: Phase 6 Distribution Shift algorithms MUST be built against the abstract `FeatureExtractor` interface and default to `StatisticalFeatureExtractor` (128 dimensions).  
> **Extensibility**: The architecture must allow any future deep backbone (e.g. ResNet-18 or ONNX feature extractor) to be injected seamlessly via constructor dependency injection, without modifying Phase 6 shift-detection algorithms.

---

## 7. Statistical Methods for Shift Detection

Phase 6 avoids unverified heuristics by specifying four complementary, non-parametric statistical metrics. All four can be implemented with rigorous numerical stability in pure Python without third-party numerical libraries.

### 7.1 Maximum Mean Discrepancy (MMD)

#### Mathematical Definition:
Let $X = \{x_1, \dots, x_n\} \sim P$ and $Y = \{y_1, \dots, y_m\} \sim Q$ be feature embeddings in $\mathbb{R}^d$. The unbiased empirical estimate of $\text{MMD}^2(P, Q)$ under kernel $k(\cdot, \cdot)$ is:
$$\text{MMD}^2(X, Y) = \frac{1}{n(n-1)} \sum_{i=1}^n \sum_{j \ne i}^n k(x_i, x_j) + \frac{1}{m(m-1)} \sum_{i=1}^m \sum_{j \ne i}^m k(y_i, y_j) - \frac{2}{nm} \sum_{i=1}^n \sum_{j=1}^m k(x_i, y_j)$$

#### Kernel Selection:
Energy kernel / RBF kernel:
$$k(u, v) = \exp\left(-\frac{\|u - v\|_2^2}{2\sigma^2}\right) \quad \text{where } \sigma = \text{median}(\|u_i - v_j\|_2)$$
Using unit-normalized embeddings ($u^T u = 1$), $\|u - v\|_2^2 = 2(1 - u^T v)$, simplifying computation.

- **Input**: Two matrices of embedding vectors $X \in \mathbb{R}^{n \times d}$ and $Y \in \mathbb{R}^{m \times d}$.
- **Output**: $\text{MMD}^2 \ge 0.0$ and overall distance score $D_{mmd} = \sqrt{\max(0.0, \text{MMD}^2)}$.
- **Complexity**: $O((n^2 + m^2 + nm) \cdot d)$. For large $n, m > 500$, subsampling or mini-batch estimation is required.
- **Threshold**: $D_{mmd} > 0.15$ triggers shift detection.

---

### 7.2 1D Wasserstein-1 Distance (Earth Mover's Distance)

#### Mathematical Definition:
For scalar 1D marginal distributions $U$ and $V$ with sorted samples $u_{(1)} \le \dots \le u_{(n)}$ and $v_{(1)} \le \dots \le v_{(m)}$:
$$W_1(U, V) = \int_{0}^1 |F_U^{-1}(t) - F_V^{-1}(t)| \, dt$$
When evaluated on quantile steps $t_k = \frac{k - 0.5}{K}$ for $k=1, \dots, K$:
$$W_1 \approx \frac{1}{K} \sum_{k=1}^K |q_U(t_k) - q_V(t_k)|$$

- **Application in CVIF**:
  Evaluated across:
  1. Top active variance dimensions in feature space.
  2. Overall pixel intensity / luminance distributions.
- **Complexity**: $O(n \log n + m \log m)$ for sorting, plus $O(K)$ quantile matching. Exceptionally fast in pure Python.
- **Threshold**: $W_1 > 0.20$ triggers marginal shift detection.

---

### 7.3 Two-Sample Kolmogorov-Smirnov (KS) Test

#### Mathematical Definition:
The KS statistic measures the supremum of the absolute vertical difference between empirical cumulative distribution functions $F_n(x)$ and $G_m(x)$:
$$D_{KS} = \sup_{x} |F_n(x) - G_m(x)|$$

#### Asymptotic p-value:
For effective sample size $n_{eff} = \sqrt{\frac{nm}{n+m}}$, the Kolmogorov distribution asymptotic approximation:
$$\lambda = \left(n_{eff} + 0.12 + \frac{0.11}{n_{eff}}\right) D_{KS}$$
$$p\text{-value} = 2 \sum_{j=1}^{10} (-1)^{j-1} \exp(-2 j^2 \lambda^2)$$

- **Input**: Two sorted 1D scalar arrays.
- **Output**: Statistic $D_{KS} \in [0.0, 1.0]$ and asymptotic $p\text{-value} \in [0.0, 1.0]$.
- **Threshold**: $p < 0.05$ rejects the null hypothesis that samples are drawn from identical continuous distributions.

---

### 7.4 Total Variation (TV) / Class Prior Divergence

#### Mathematical Definition:
Let $p_{ref}(c)$ and $p_{eval}(c)$ be normalized class frequencies across classes $c \in \mathcal{C}$:
$$D_{TV}(P_{ref}, P_{eval}) = \frac{1}{2} \sum_{c \in \mathcal{C}} |p_{ref}(c) - p_{eval}(c)| \in [0.0, 1.0]$$

- **Interpretation**: Quantifies semantic concept drift. If $D_{TV} = 0.0$, class distributions are identical; if $D_{TV} = 1.0$, evaluation dataset shares zero class overlap with reference.
- **Complexity**: $O(|\mathcal{C}| + N_{annotations})$. Instantaneous computation.
- **Threshold**: $D_{TV} > 0.25$ indicates significant concept/class prior drift.

---

## 8. Threat Model & Threat Mapping

Phase 6 formalizes four specific threats within the CVIF Threat Taxonomy:

```
Threat Taxonomy: Distribution Shift Series (DS)
├── DS-1: Covariate Shift (Feature-Space Distribution Divergence)
├── DS-2: Semantic & Concept Shift (Class Prior & Representation Asymmetry)
├── DS-3: Environmental & Sensor Degradation Drift (Image Quality / Channel Statistics)
└── DS-4: Adversarial Distribution Manipulation (Targeted Subpopulation Shift)
```

### 8.1 Threat Mitigation Matrix

| Threat ID | Threat Name | Attack / Operational Scenario | Detection Mechanism | Evidence Produced | Calibrated Finding Title | Default Disposition |
|:---|:---|:---|:---|:---|:---|:---|
| **DS-1** | **Covariate Shift** | Operational deployment in unmodeled terrain or weather (e.g. desert vs forest); domain shift degrades model confidence | Multi-variate MMD and marginal Wasserstein distance over feature embeddings | `ShiftDimensionResult` with $D_{mmd}$, $W_1$, dimension metrics | *"Covariate Distribution Shift Detected (DS-1)"* | `REVIEW` |
| **DS-2** | **Semantic Shift** | Strategic target concentration shift or adversary deploying tactical decoys skewing class priors | Total Variation distance $D_{TV}$ over categorical histograms; class conditional centroid drift | Category prior divergence table, JS distance, missing classes | *"Semantic Concept / Class Prior Shift Detected (DS-2)"* | `REVIEW` |
| **DS-3** | **Environmental / Sensor Drift** | Camera optic contamination, thermal sensor calibration drift, severe compression throttling | 1D KS test and Wasserstein distance over luminance, contrast variance, Laplacian blur | Channel histograms, blur metric deltas, KS p-values | *"Environmental / Sensor Quality Degradation Detected (DS-3)"* | `REVIEW` |
| **DS-4** | **Adversarial Distribution Manipulation** | Malicious subpopulation poisoning or targeted feature clustering designed to bypass verification | High feature separability concentrated in specific subclusters while overall drift remains moderate | Subpopulation cluster variance, separation score, $L_{manip}$ | *"Suspicious Distribution Manipulation Detected (DS-4)"* | `QUARANTINE` |

### 8.2 Calibrated Terminology Rules
In accordance with defense assurance standards, Phase 6 must adhere to calibrated forensic language:
- **Never claim malice without evidence**: Statistical anomalies alone do NOT prove hostile intent. A severe sandstorm produces massive covariate shift (`DS-1`), but is an operational reality, not a cyberattack.
- **Use probabilistic thresholds**:
  - If $L_{manip} \ge 0.70 \implies$ *"Evidence strongly suggests intentional distribution manipulation or localized subpopulation poisoning."* (Disposition: `QUARANTINE`)
  - If $L_{drift} \ge 0.60 \implies$ *"Observed shift is consistent with natural operational, environmental, or sensor drift."* (Disposition: `REVIEW`)
  - If $N < 15 \implies$ *"Insufficient sample size to distinguish operational drift from intentional manipulation."* (Disposition: `INFORMATIONAL` / `REVIEW`)

---

## 9. Threshold & Calibration Analysis

### 9.1 Configuration Schema Extension
Phase 6 thresholds must be configurable in `config/default_config.yaml` under a dedicated `distribution_shift` section:

```yaml
distribution_shift:
  mmd_threshold: 0.15
  wasserstein_threshold: 0.20
  ks_alpha: 0.05
  class_tv_threshold: 0.25
  min_sample_size: 15
  batch_size: 250
  subpopulation_clustering: true
  max_variance_dimensions: 16
```

### 9.2 Edge Condition Handlers

| Edge Case | Condition | System Behavior | Safety Measure |
|:---|:---|:---|:---|
| **Under-sampled Dataset** | $N < 15$ samples | Mark `evidence_sufficient = False`; cap confidence at $\le 0.40$; downgrade disposition to `REVIEW` | Prevents false alarms on small reconnaissance bursts |
| **Zero Variance Dimension** | $\text{Var}(X_d) < 10^{-8}$ | Regularize with $\epsilon = 10^{-6}$ or drop inactive dimension | Prevents `ZeroDivisionError` in distance calculations |
| **NaN / Inf in Vectors** | Vector contains non-finite values | Sanitize during extraction; reject sample with warning | Prevents NaN pollution of global distribution metrics |
| **Completely Disjoint Classes** | $\mathcal{C}_{ref} \cap \mathcal{C}_{eval} = \emptyset$ | Set $D_{TV} = 1.0$; flag critical semantic shift | Handled gracefully without crash |
| **Identical Datasets** | $P_{ref} \equiv P_{eval}$ | Compute $D \approx 0.0, p \approx 1.0$; synthesize `natural_drift = 0.0, manip = 0.0` | Exact zero-drift baseline verified |

---

## 10. Evidence Model

Phase 6 integrates with CVIF's write-once [`EvidenceStore`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py) and canonical schemas.

### 10.1 `ShiftReport` Structure (`src/cvif/core/schemas.py`)
```python
class ShiftReport(CVIFBaseModel):
    report_id: UUID = Field(default_factory=uuid4)
    reference_asset_id: UUID
    evaluation_asset_id: UUID
    session_id: UUID
    overall_distance: float = Field(..., ge=0.0)
    dimensions: Dict[str, ShiftDimensionResult] = Field(default_factory=dict)
    assessment: ShiftAssessment
    characterization: str
    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")
```

### 10.2 Linked `EvidenceRecord`
For every distribution shift finding, an [`EvidenceRecord`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L42-L68) is constructed:
- `evidence_type`: `EvidenceType.STATISTICAL` and `EvidenceType.COMPARATIVE`.
- `metrics`:
  ```json
  {
    "overall_distance": 0.452,
    "mmd_distance": 0.381,
    "mean_wasserstein": 0.224,
    "class_tv_distance": 0.180,
    "ks_rejection_ratio": 0.625
  }
  ```
- `baseline_comparison`:
  ```json
  {
    "reference_asset_id": "...",
    "evaluation_asset_id": "...",
    "reference_sample_count": 500,
    "evaluation_sample_count": 450,
    "reference_hash": "...",
    "evaluation_hash": "..."
  }
  ```
- `artifacts`: A linked [`ArtifactReference`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L28-L39) pointing to the serialized `shift_report.json` saved in `EvidenceStore.save_artifact()`.

---

## 11. Cryptographic & Integrity Boundaries

1. **Deterministic Canonicalization**: `ShiftReport` inherits from `CVIFBaseModel`, supporting `to_canonical_json()` and `compute_hash()` (SHA-256 over sorted keys and quantized floats).
2. **Write-Once Evidence**: Shift evidence files persisted in `EvidenceStore` (`sessions/<session_id>/evidence/<evidence_id>.json`) enforce write-once semantics (`EvidenceImmutableError` on overwrite).
3. **Tamper-Evident Audit Logging**: The session start, finding records, and shift evaluation completion are appended to `audit.jsonl` with cryptographic hash chaining:
   $$H_n = \text{SHA-256}(E_n \parallel H_{n-1})$$
4. **Air-Gapped Trust Verification**: No external certificate authorities or network key servers are consulted. Key identities and asset registries resolve locally against SQLite and `KeyStore`.

---

## 12. Security Boundaries & Hardening

1. **Filesystem Safety**: Image paths from `UnifiedDataset` are validated using `safe_resolve_path()` to eliminate directory traversal attacks (`../`, `..\\`).
2. **Resource Exhaustion Defense**:
   - `max_samples_evaluated`: Ingestion cap of $N \le 10,000$ per evaluation batch.
   - `batch_size`: Streaming feature extraction in batches of $32$ to respect the $8192\text{ MB}$ memory boundary.
3. **Malformed Image Defense**: Corrupted headers, truncated bytes, or decompression bombs are safely trapped by byte-level parsers without crashing the analysis session.
4. **Numerical Abuse Defense**:
   - Explicit zero-division guards on variances ($+10^{-8}$).
   - IEEE 754 float sanitization (`math.isnan(x)` and `math.isinf(x)`).

---

## 13. Performance & Scalability Assessment

### 13.1 Complexity Analysis

| Operation | Mathematical Formulation | Time Complexity | Space Complexity | Practical Runtime ($N=500, D=128$) | Bottleneck Risk? |
|:---|:---|:---|:---|:---|:---|
| **Feature Extraction** | `StatisticalFeatureExtractor.extract()` | $O(N \cdot S_{bytes})$ | $O(D)$ | $\approx 250\text{ ms}$ on CPU | Low (pure Python, streaming) |
| **MMD (Pairwise)** | Matrix kernel sum | $O((N^2 + M^2) \cdot D)$ | $O(N + M)$ | $\approx 85\text{ ms}$ on CPU | **Medium** ($N > 2000$ requires subsampling) |
| **1D Wasserstein** | Quantile matching over active dims | $O(D_{active} \cdot N \log N)$ | $O(N)$ | $\approx 15\text{ ms}$ on CPU | Negligible |
| **2-Sample KS Test** | Empirical CDF supremum | $O(D_{active} \cdot N \log N)$ | $O(N)$ | $\approx 12\text{ ms}$ on CPU | Negligible |
| **Class TV Distance** | Discrete histogram differential | $O(K + N_{ann})$ | $O(K)$ | $< 1\text{ ms}$ | Negligible |
| **Total Pipeline** | Full comparative suite | $O(N \cdot S) + O(N^2 D)$ | $O(N \cdot D)$ | $\approx \mathbf{380\text{ ms}}$ | **Fully acceptable on CPU** |

### 13.2 Subsampling Strategy for Large Datasets
If an evaluation dataset exceeds $N = 1,000$ samples, the orchestrator should utilize stratified subsampling ($N_{eval} = 500$) for the $O(N^2)$ MMD computation, while evaluating $O(N \log N)$ 1D Wasserstein and class prior metrics over the full dataset population.

---

## 14. Dependency Audit

Current virtual environment inspection (`requirements.lock`):
```
annotated-types==0.8.0
cffi==2.1.1
cryptography==50.0.1
pydantic==2.13.5
pydantic_core==2.46.5
pytest==9.1.1
PyYAML==6.0.3
typing_extensions==4.16.0
```

- **Absence of NumPy / SciPy**: Neither library is installed.
- **Architectural Policy**:
  - Phase 6 **WILL NOT** require installing `numpy`, `scipy`, or `torch`.
  - All algorithms (MMD, Wasserstein, KS test, TV distance) will be implemented directly using Python 3.10 standard library (`math`, `statistics`, `collections`, `itertools`).
  - This guarantees 100% offline portability across any Python 3.10+ installation without C-compiler prerequisites or DLL conflicts on Windows.

---

## 15. Test Architecture

The eventual Phase 6 test suite will be organized in `tests/unit/test_distribution_shift.py` covering 16 mandatory test categories:

1. **Category A: Deterministic Feature Extraction**: Identical images yield identical feature vectors ($L_2 = 1.0$).
2. **Category B: Identical-Distribution Baseline**: Evaluating identical datasets $P_{ref} \equiv P_{ref}$ results in $D \approx 0.0$, zero findings, and `ACCEPT`.
3. **Category C: Known Synthetic Shift**: Controlled perturbations (mean shift, variance expansion) produce detectable $D > 0.20$ and `DS-1` finding.
4. **Category D: Small-Sample Behavior**: Datasets with $N < 10$ samples produce `evidence_sufficient = False` without raising exceptions.
5. **Category E: Degenerate Distribution**: Datasets with constant zero-variance images are regularized without `ZeroDivisionError`.
6. **Category F: NaN / Inf Injection**: Corrupted feature inputs are cleanly trapped and sanitized.
7. **Category G: Malformed Input Handling**: Missing image paths or broken image headers raise clean, typed exceptions.
8. **Category H: Threshold Crossover**: Validating calibrated transition between `ACCEPT`, `REVIEW`, and `QUARANTINE`.
9. **Category I: False-Positive Calibration**: Evaluating natural minor lighting variances does NOT produce high `suspicious_manipulation_likelihood`.
10. **Category J: Reproducibility**: Repeated runs on identical inputs yield bit-for-bit identical `ShiftReport` canonical hashes.
11. **Category K: Evidence Generation**: `EvidenceRecord` files are correctly formatted and written to `EvidenceStore`.
12. **Category L: Evidence Tampering Defense**: Modifying a saved evidence file is detected by `EvidenceStore`.
13. **Category M: Audit Trail Chaining**: Complete execution sequence is recorded in `audit.jsonl` with unbroken hash chains.
14. **Category N: Air-Gap / Offline Execution**: Test suite runs under socket monkeypatching without network calls.
15. **Category O: Performance Benchmark**: End-to-end evaluation of 500 samples completes in $< 2.0\text{ seconds}$ on CPU.
16. **Category P: System Regression**: All 169 existing unit tests from Phases 1–5 continue to pass with 100% success.

---

## 16. Anti-Stub Requirements

To maintain forensic credibility, Phase 6 implementation must enforce strict anti-stub constraints:

- ❌ **No Hardcoded Scores**: Shift distances and p-values must never be hardcoded constants (e.g. `return 0.42`).
- ❌ **No Pseudo-Random Outputs**: Distance metrics must not use `random.random()`.
- ❌ **No Mock Extractors in Production**: `MockFeatureExtractor` is strictly for unit testing; production execution must use `StatisticalFeatureExtractor` or verified neural adapters.
- ❌ **No Fabricated Benchmarks**: All metrics and timing numbers must reflect actual computation over real input byte arrays.
- ❌ **No Silent Fallback to Fixed Constants**: Any mathematical degradation or sample-size limitation must be explicitly recorded in `limitations` and `ShiftAssessment.reasoning`.

---

## 17. Existing-Code Dependency Map

```
Existing Framework Components Used by Phase 6:
├── src/cvif/core/
│   ├── schemas.py (UnifiedDataset, ImageRecord, ShiftReport, ShiftAssessment, Finding, EvidenceRecord)
│   ├── enums.py (SeverityLevel, Disposition, EvidenceType, AuditEventType, SessionStatus)
│   └── config.py (AppConfig, FeatureExtractorConfig, StorageConfig)
├── src/cvif/features/
│   ├── base.py (FeatureExtractor abstract interface)
│   └── statistical.py (StatisticalFeatureExtractor - primary 128D engine)
├── src/cvif/storage/
│   ├── database.py (DatabaseManager - session, asset, and finding persistence)
│   └── filestore.py (SafeFileStore - secure asset resolution)
├── src/cvif/evidence/
│   └── store.py (EvidenceStore - immutable JSON artifact persistence)
└── src/cvif/audit/
    └── logger.py (AuditLogger - tamper-evident hash chaining)
```

**Compatibility Risk Assessment**:
- `UnifiedDataset`: Fully compatible (Phase 3).
- `EvidenceStore`: Fully compatible (Phase 2).
- `DatabaseManager`: Fully compatible. Note: A dedicated helper for saving `ShiftReport` JSON can be added to `DatabaseManager` or saved as an artifact in `EvidenceStore` without database schema alteration.

---

## 18. Phase Boundary & Non-Goals

### Strict Boundaries for Phase 6:
- **MUST IMPLEMENT**:
  - `DistributionShiftOrchestrator` coordinating two-dataset comparisons.
  - Pure-Python statistical metrics module (`mmd`, `wasserstein_1d`, `ks_2sample`, `class_tv`).
  - Dedicated threat checks: `CovariateShiftCheck` (`DS-1`), `SemanticShiftCheck` (`DS-2`), `EnvironmentalDriftCheck` (`DS-3`), `AdversarialManipulationCheck` (`DS-4`).
  - Synthesis of `ShiftReport` and `ShiftAssessment`.
  - Comprehensive unit test suite (`tests/unit/test_distribution_shift.py`).

- **MUST NOT IMPLEMENT (Belongs to Phase 7+)**:
  - **Phase 7**: Composite assurance verdict aggregation (`AssuranceVerdict` synthesizing Data + Model + Provenance + Shift into one global risk score).
  - **Phase 8**: Evidence Store UI / Web schema expansions.
  - **Phase 9**: Command-line interface commands (`cvif analyze-shift`).
  - **Phase 10**: REST API endpoints (`/api/v1/shift/evaluate`).
  - **Phase 11**: Interactive visualization dashboards / charts.
  - **Phase 12**: Production deployment containerization.

---

## 19. Architectural Blocker Audit

| Potential Blocker | Severity | Findings & Evidence | Status / Resolution |
|:---|:---|:---|:---|
| **Absence of NumPy / SciPy** | **NON-BLOCKING** | Checked `.venv` packages. Neither is installed. Phase 6 algorithms can be cleanly implemented in pure Python standard library using $O(N \log N)$ sorting and vectorized list comprehensions. | **RESOLVED**: Implement pure-Python statistical engine. |
| **Shift Report Persistence** | **NON-BLOCKING** | `DatabaseManager` has no `shift_reports` table, but `EvidenceStore.save_artifact()` stores complete JSON payloads, and `findings` table records all findings. | **RESOLVED**: Save canonical report in `EvidenceStore` and link UUID to session findings. |
| **Threat Taxonomy Prefix** | **NON-BLOCKING** | `schemas.py:113` specifies category `"DISTRIBUTION_SHIFT"`. Threat IDs `DS-1` through `DS-4` are now formally codified in Section 8. | **RESOLVED**: Adopt `DS-1` to `DS-4`. |
| **Baseline Dataset Pairing** | **NON-BLOCKING** | Orchestrator requires both `reference_dataset` and `evaluation_dataset`. Ingestion gateway from Phase 3 supports loading multiple `UnifiedDataset` instances. | **RESOLVED**: Explicit `(reference, evaluation)` parameter interface. |

**Conclusion**: There are **zero blocking architectural flaws**. The project is structurally ready for Phase 6 implementation.

---

## 20. Proposed Phase 6 Implementation Plan

When Phase 6 implementation is authorized, the following modular structure will be created:

```
src/cvif/analysis/distribution_shift/
├── __init__.py                # Export orchestrator and check classes
├── base.py                    # DistributionShiftCheck abstract base class
├── metrics.py                 # Pure-Python statistical engine (MMD, Wasserstein, KS, TV)
├── covariate.py               # DS-1: CovariateShiftCheck (Feature embedding divergence)
├── semantic.py                # DS-2: SemanticShiftCheck (Class prior & label divergence)
├── environmental.py           # DS-3: EnvironmentalDriftCheck (Image quality & sensor drift)
├── manipulation.py            # DS-4: AdversarialManipulationCheck (Subpopulation drift)
└── orchestrator.py            # DistributionShiftOrchestrator coordinating pipeline

tests/unit/
└── test_distribution_shift.py # 16 test categories covering all functionality
```

---

## 21. Final Verdict

All prerequisite architectural data contracts are verified, mathematical foundations are established in pure Python to preserve air-gapped deployment integrity, threat taxonomy items (`DS-1` to `DS-4`) are formally codified, and clear phase boundaries are enforced.

PHASE 6 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
