"""Pure-Python statistical distance and divergence metrics for distribution shift analysis.

Implements Maximum Mean Discrepancy (MMD), 1D Wasserstein-1 Earth Mover's Distance,
Two-Sample Kolmogorov-Smirnov (KS) test, Class Prior Total Variation (TV), and
image-quality scalar distributions without NumPy, SciPy, or Torch.
"""

import math
from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


def compute_wasserstein_1d(u: Sequence[float], v: Sequence[float]) -> float:
    """Compute exact 1D Wasserstein-1 (Earth Mover's) distance between two empirical distributions.

    Evaluates the integral of absolute difference between empirical cumulative distribution
    functions: W_1(U, V) = \\int |F_u(x) - F_v(x)| dx in O((N + M) log(N + M)) time.
    """
    if not u or not v:
        return 0.0

    # Numerical validation
    for x in u:
        if math.isnan(x) or math.isinf(x):
            raise ValueError("Distribution u contains non-finite (NaN or Inf) values")
    for y in v:
        if math.isnan(y) or math.isinf(y):
            raise ValueError("Distribution v contains non-finite (NaN or Inf) values")

    u_sorted = sorted(u)
    v_sorted = sorted(v)

    if u_sorted == v_sorted:
        return 0.0

    n = len(u_sorted)
    m = len(v_sorted)

    # Collect all unique sample locations across both populations
    all_vals = sorted(list(set(u_sorted) | set(v_sorted)))
    if len(all_vals) <= 1:
        return 0.0

    i = 0
    j = 0
    total_work = 0.0

    # Step-integral between consecutive unique values
    for idx in range(len(all_vals) - 1):
        val = all_vals[idx]
        next_val = all_vals[idx + 1]

        while i < n and u_sorted[i] <= val:
            i += 1
        while j < m and v_sorted[j] <= val:
            j += 1

        f_u = i / n
        f_v = j / m
        diff = abs(f_u - f_v)
        interval = next_val - val
        total_work += diff * interval

    return round(total_work, 8)


def compute_ks_2sample(u: Sequence[float], v: Sequence[float]) -> Tuple[float, float]:
    """Compute two-sample Kolmogorov-Smirnov test statistic and asymptotic p-value.

    Tests the null hypothesis that u and v are drawn from identical continuous distributions.
    Returns (statistic, p_value) where statistic in [0.0, 1.0] is the supremum CDF delta.
    """
    if not u or not v:
        return (0.0, 1.0)

    for x in u:
        if math.isnan(x) or math.isinf(x):
            raise ValueError("Distribution u contains non-finite values")
    for y in v:
        if math.isnan(y) or math.isinf(y):
            raise ValueError("Distribution v contains non-finite values")

    u_sorted = sorted(u)
    v_sorted = sorted(v)

    if u_sorted == v_sorted:
        return (0.0, 1.0)

    n = len(u_sorted)
    m = len(v_sorted)
    all_vals = sorted(list(set(u_sorted) | set(v_sorted)))

    i = 0
    j = 0
    d_max = 0.0

    for val in all_vals:
        while i < n and u_sorted[i] <= val:
            i += 1
        while j < m and v_sorted[j] <= val:
            j += 1
        diff = abs(i / n - j / m)
        if diff > d_max:
            d_max = diff

    # Asymptotic p-value calculation via Kolmogorov distribution
    n_eff = math.sqrt((n * m) / (n + m))
    if n_eff <= 0.0 or d_max <= 0.0:
        return (round(d_max, 6), 1.0)

    lambda_val = (n_eff + 0.12 + 0.11 / n_eff) * d_max
    if lambda_val <= 0.0:
        p_val = 1.0
    elif lambda_val > 4.0:
        p_val = 0.0
    else:
        p_val = 0.0
        for k in range(1, 101):
            term = 2.0 * ((-1) ** (k - 1)) * math.exp(-2.0 * (k * lambda_val) ** 2)
            p_val += term
            if abs(term) < 1e-15:
                break
        p_val = max(0.0, min(1.0, p_val))

    return (round(d_max, 6), round(p_val, 6))


def compute_mmd(
    X: Sequence[Sequence[float]],
    Y: Sequence[Sequence[float]],
    gamma: Optional[float] = None,
    max_samples: int = 500,
) -> float:
    """Compute unbiased Maximum Mean Discrepancy (MMD) with an RBF kernel.

    Measures distribution divergence between multi-dimensional embedding matrices.
    Returns non-negative distance score sqrt(max(0, MMD^2)).
    """
    if not X or not Y:
        return 0.0

    # Dimension and numerical integrity validation
    dim = len(X[0])
    if dim == 0:
        return 0.0

    for idx, vec in enumerate(X):
        if len(vec) != dim:
            raise ValueError(f"X vector at index {idx} has length {len(vec)}, expected {dim}")
        for val in vec:
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"X vector at index {idx} contains non-finite values")

    for idx, vec in enumerate(Y):
        if len(vec) != dim:
            raise ValueError(f"Y vector at index {idx} has length {len(vec)}, expected {dim}")
        for val in vec:
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Y vector at index {idx} contains non-finite values")

    # Identical check
    if len(X) == len(Y) and all(x == y for x, y in zip(X, Y)):
        return 0.0

    # Deterministic subsampling for O(N^2) scalability
    n_total = len(X)
    m_total = len(Y)
    sub_X = (
        [X[i] for i in range(0, n_total, max(1, n_total // max_samples))][:max_samples]
        if n_total > max_samples
        else list(X)
    )
    sub_Y = (
        [Y[i] for i in range(0, m_total, max(1, m_total // max_samples))][:max_samples]
        if m_total > max_samples
        else list(Y)
    )

    n = len(sub_X)
    m = len(sub_Y)

    # Heuristic bandwidth estimation if not supplied
    if gamma is None:
        sample_x = sub_X[: min(n, 40)]
        sample_y = sub_Y[: min(m, 40)]
        sq_dists = []
        for u in sample_x:
            for v in sample_y:
                dist_sq = sum((a - b) ** 2 for a, b in zip(u, v))
                if dist_sq > 1e-8:
                    sq_dists.append(dist_sq)
        if sq_dists:
            med_sq = statistics.median(sq_dists)
            gamma = 1.0 / (2.0 * max(1e-6, med_sq))
        else:
            gamma = 0.5

    def rbf_k(u: Sequence[float], v: Sequence[float]) -> float:
        sq = sum((a - b) ** 2 for a, b in zip(u, v))
        return math.exp(-gamma * sq)

    # Unbiased empirical estimator
    if n > 1:
        sum_xx = 0.0
        for i in range(n):
            for j in range(i + 1, n):
                sum_xx += rbf_k(sub_X[i], sub_X[j])
        term_xx = (2.0 * sum_xx) / (n * (n - 1))
    else:
        term_xx = 1.0

    if m > 1:
        sum_yy = 0.0
        for i in range(m):
            for j in range(i + 1, m):
                sum_yy += rbf_k(sub_Y[i], sub_Y[j])
        term_yy = (2.0 * sum_yy) / (m * (m - 1))
    else:
        term_yy = 1.0

    sum_xy = 0.0
    for i in range(n):
        for j in range(m):
            sum_xy += rbf_k(sub_X[i], sub_Y[j])
    term_xy = sum_xy / (n * m)

    mmd_sq = term_xx + term_yy - 2.0 * term_xy
    return round(math.sqrt(max(0.0, mmd_sq)), 6)


def compute_class_tv(
    ref_counts: Dict[str, int], eval_counts: Dict[str, int]
) -> Tuple[float, Dict[str, Any]]:
    """Compute Total Variation distance D_TV in [0.0, 1.0] between class frequency distributions.

    D_TV(P, Q) = 0.5 * sum_{c} |P(c) - Q(c)|.
    Returns (distance, details_dict).
    """
    all_classes = sorted(list(set(ref_counts.keys()) | set(eval_counts.keys())))
    if not all_classes:
        return 0.0, {"missing_classes": [], "new_classes": [], "tv_distance": 0.0}

    total_ref = sum(ref_counts.values())
    total_eval = sum(eval_counts.values())

    if total_ref == 0 and total_eval == 0:
        return 0.0, {"missing_classes": [], "new_classes": [], "tv_distance": 0.0}
    if total_ref == 0 or total_eval == 0:
        return 1.0, {
            "missing_classes": [c for c in ref_counts if ref_counts[c] > 0],
            "new_classes": [c for c in eval_counts if eval_counts[c] > 0],
            "tv_distance": 1.0,
        }

    p_ref = {c: ref_counts.get(c, 0) / total_ref for c in all_classes}
    p_eval = {c: eval_counts.get(c, 0) / total_eval for c in all_classes}

    tv = 0.5 * sum(abs(p_ref[c] - p_eval[c]) for c in all_classes)

    missing = [c for c in all_classes if p_ref[c] > 0 and p_eval[c] == 0]
    new_c = [c for c in all_classes if p_ref[c] == 0 and p_eval[c] > 0]

    return round(min(1.0, max(0.0, tv)), 6), {
        "missing_classes": missing,
        "new_classes": new_c,
        "ref_proportions": {c: round(p_ref[c], 4) for c in all_classes},
        "eval_proportions": {c: round(p_eval[c], 4) for c in all_classes},
        "tv_distance": round(tv, 6),
    }


def compute_multivariate_wasserstein_mean(
    X: Sequence[Sequence[float]],
    Y: Sequence[Sequence[float]],
    max_dims: int = 16,
) -> float:
    """Compute average 1D Wasserstein distance across top active feature dimensions."""
    if not X or not Y:
        return 0.0

    dim = len(X[0])
    if dim != len(Y[0]):
        raise ValueError(f"Mismatched feature dimensions: {dim} vs {len(Y[0])}")

    # Determine which dimensions to evaluate
    if dim <= max_dims:
        dims_to_eval = list(range(dim))
    else:
        # Pick dimensions with highest variance in X
        variances = []
        for d in range(dim):
            col = [vec[d] for vec in X]
            var = statistics.variance(col) if len(col) > 1 else 0.0
            variances.append((var, d))
        variances.sort(reverse=True)
        dims_to_eval = [d for _, d in variances[:max_dims]]

    w_distances = []
    for d in dims_to_eval:
        col_x = [vec[d] for vec in X]
        col_y = [vec[d] for vec in Y]
        w = compute_wasserstein_1d(col_x, col_y)
        w_distances.append(w)

    return round(statistics.mean(w_distances), 6) if w_distances else 0.0


def extract_raw_pixel_bytes(data: bytes) -> bytes:
    """Extract uncompressed pixel byte stream from image container formats (PNG, BMP) where feasible."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        try:
            import zlib
            idx = 8
            idat_parts = []
            while idx < len(data) - 4:
                length = int.from_bytes(data[idx : idx + 4], "big")
                chunk_type = data[idx + 4 : idx + 8]
                if chunk_type == b"IDAT":
                    idat_parts.append(data[idx + 8 : idx + 8 + length])
                elif chunk_type == b"IEND":
                    break
                idx += 12 + length
            if idat_parts:
                return zlib.decompress(b"".join(idat_parts))
        except Exception:
            pass
    elif data.startswith(b"BM") and len(data) >= 26:
        try:
            offset = int.from_bytes(data[10:14], "little")
            return data[offset:]
        except Exception:
            pass
    return data


def extract_image_quality_scalars(
    data: bytes, width: int = 0, height: int = 0
) -> Dict[str, float]:
    """Extract low-level image quality and sensor statistics from raw bytes in pure Python.

    Extracts:
    - luminance: mean byte value [0.0, 1.0]
    - contrast: standard deviation of byte values [0.0, 1.0]
    - sharpness: average adjacent byte difference [0.0, 1.0]
    - aspect_ratio: w / max(1, h)
    - size_kb: len(data) / 1024.0
    """
    if not data:
        return {
            "luminance": 0.0,
            "contrast": 0.0,
            "sharpness": 0.0,
            "aspect_ratio": 1.0,
            "size_kb": 0.0,
        }

    pixel_data = extract_raw_pixel_bytes(data)

    # Downsample if pixel bytes are very large (sample up to 4096 bytes)
    pix_len = len(pixel_data)
    if pix_len > 4096:
        step = pix_len // 4096
        sample_bytes = [pixel_data[i] for i in range(0, pix_len, step)][:4096]
    else:
        sample_bytes = list(pixel_data)

    n = len(sample_bytes)
    mean_val = sum(sample_bytes) / n
    variance = sum((b - mean_val) ** 2 for b in sample_bytes) / n
    std_dev = math.sqrt(variance)

    # Sharpness / high-frequency gradient
    deltas = [abs(sample_bytes[i] - sample_bytes[i - 1]) for i in range(1, n)]
    sharpness = (sum(deltas) / len(deltas)) if deltas else 0.0

    aspect = (float(width) / float(height)) if (width > 0 and height > 0) else 1.0

    return {
        "luminance": round(mean_val / 255.0, 6),
        "contrast": round(std_dev / 255.0, 6),
        "sharpness": round(sharpness / 255.0, 6),
        "aspect_ratio": round(aspect, 4),
        "size_kb": round(len(data) / 1024.0, 4),
    }
