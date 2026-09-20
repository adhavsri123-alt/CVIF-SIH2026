"""Deterministic canonical serialization and numerical quantization for inference provenance."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Union


def quantize_floats(obj: Any, key_context: str = "") -> Any:
    """Recursively quantize floating point values in nested dictionaries and lists.
    
    Rules:
    - Bounding box coordinates: 6 decimal places.
    - Confidence scores: 4 decimal places.
    - General floats: 6 decimal places.
    """
    if isinstance(obj, dict):
        return {k: quantize_floats(v, key_context=k) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        # Check if list represents a bounding box
        is_bbox = any(b_name in key_context.lower() for b_name in ["bbox", "bboxes"])
        if is_bbox and all(isinstance(x, (int, float)) for x in obj):
            return [round(float(x), 6) for x in obj]
        return [quantize_floats(item, key_context=key_context) for item in obj]
    elif isinstance(obj, float):
        # Determine quantization precision based on key context
        lower_ctx = key_context.lower()
        if any(c_name in lower_ctx for c_name in ["confidence", "conf", "score", "prob"]):
            return round(obj, 4)
        elif any(b_name in lower_ctx for b_name in ["bbox", "coord", "coordinate", "iou"]):
            return round(obj, 6)
        else:
            return round(obj, 6)
    elif isinstance(obj, int):
        return obj
    elif isinstance(obj, (str, bool)) or obj is None:
        return obj
    elif hasattr(obj, "model_dump"):
        return quantize_floats(obj.model_dump(mode="json"), key_context=key_context)
    else:
        return str(obj)


def format_canonical_timestamp(dt: datetime) -> str:
    """Format datetime into a deterministic UTC ISO-8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_canonical_payload_dict(record: Any) -> Dict[str, Any]:
    """Construct the standardized, cryptographically bound dictionary for an InferenceRecord."""
    # Handle output conversion
    raw_output = getattr(record, "output", {})
    if hasattr(raw_output, "model_dump"):
        output_dict = raw_output.model_dump(mode="json")
    elif isinstance(raw_output, dict):
        output_dict = raw_output
    else:
        output_dict = {"data": str(raw_output)}

    raw_inference_config = getattr(record, "inference_config", {})
    if hasattr(raw_inference_config, "model_dump"):
        inf_cfg = raw_inference_config.model_dump(mode="json")
    elif isinstance(raw_inference_config, dict):
        inf_cfg = raw_inference_config
    else:
        inf_cfg = {"config": str(raw_inference_config)}

    ts = getattr(record, "timestamp", None)
    if isinstance(ts, datetime):
        ts_str = format_canonical_timestamp(ts)
    elif isinstance(ts, str):
        ts_str = ts
    else:
        ts_str = format_canonical_timestamp(datetime.now(timezone.utc))

    session_id_val = getattr(record, "session_id", None)
    session_id_str = str(session_id_val) if session_id_val else ""

    record_id_val = getattr(record, "record_id", None)
    record_id_str = str(record_id_val) if record_id_val else ""

    payload = {
        "schema_version": getattr(record, "schema_version", "1.0"),
        "session_id": session_id_str,
        "record_id": record_id_str,
        "producer_id": getattr(record, "producer_id", None),
        "signing_key_id": getattr(record, "signing_key_id", None),
        "timestamp": ts_str,
        "sequence_number": int(getattr(record, "sequence_number", 0)),
        "nonce": str(getattr(record, "nonce", "")),
        "input_image_hash": str(getattr(record, "input_image_hash", "")),
        "model_id": str(getattr(record, "model_id", "")),
        "model_weight_digest": str(getattr(record, "model_weight_digest", "")),
        "preprocessing_config_hash": str(getattr(record, "preprocessing_config_hash", "")),
        "inference_config": quantize_floats(inf_cfg),
        "output": quantize_floats(output_dict),
        "previous_record_hash": getattr(record, "previous_record_hash", None),
    }
    return payload


def canonical_json_dumps(data: Dict[str, Any]) -> str:
    """Produce deterministic JSON with sorted keys, no whitespace, and standard ASCII escaping."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_payload_bytes(record: Any) -> bytes:
    """Produce the exact UTF-8 byte stream bound by HMAC or digital signature."""
    payload_dict = build_canonical_payload_dict(record)
    return canonical_json_dumps(payload_dict).encode("utf-8")
