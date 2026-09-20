"""Inference Provenance package for CVIF.

Provides:
- Mode 1: InferenceProvenanceGenerator for producing authenticated inference records.
- Mode 2: InferenceProvenanceVerifier for verifying external multi-contributor records.
- Deterministic canonical serialization and float quantization.
"""

from cvif.provenance.canonical import (
    build_canonical_payload_dict,
    canonical_json_dumps,
    canonical_payload_bytes,
    format_canonical_timestamp,
    quantize_floats,
)
from cvif.provenance.demo import (
    generate_demo_inference_record,
    get_demo_keypair,
)
from cvif.provenance.generator import InferenceProvenanceGenerator
from cvif.provenance.verifier import InferenceProvenanceVerifier

__all__ = [
    "InferenceProvenanceGenerator",
    "InferenceProvenanceVerifier",
    "generate_demo_inference_record",
    "get_demo_keypair",
    "build_canonical_payload_dict",
    "canonical_json_dumps",
    "canonical_payload_bytes",
    "format_canonical_timestamp",
    "quantize_floats",
]
