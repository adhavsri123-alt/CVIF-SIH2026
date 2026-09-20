"""Bounding box matching and Kuhn-Munkres (Hungarian algorithm) utilities."""

from typing import Any, Dict, List, Optional, Tuple

from cvif.core.schemas import DetectionOutput


def compute_iou(box1: List[float], box2: List[float]) -> float:
    """Compute Intersection-over-Union (IoU) between two bounding boxes.
    
    Coordinates must be in normalized [x_min, y_min, x_max, y_max] format.
    Returns float in range [0.0, 1.0].
    """
    if len(box1) < 4 or len(box2) < 4:
        return 0.0

    x_inter1 = max(box1[0], box2[0])
    y_inter1 = max(box1[1], box2[1])
    x_inter2 = min(box1[2], box2[2])
    y_inter2 = min(box1[3], box2[3])

    inter_w = max(0.0, x_inter2 - x_inter1)
    inter_h = max(0.0, y_inter2 - y_inter1)
    inter_area = inter_w * inter_h

    area1 = max(0.0, box1[2] - box1[0]) * max(0.0, box1[3] - box1[1])
    area2 = max(0.0, box2[2] - box2[0]) * max(0.0, box2[3] - box2[1])

    union_area = area1 + area2 - inter_area
    if union_area <= 0.0:
        return 0.0

    return min(1.0, max(0.0, inter_area / union_area))


def hungarian_match(cost_matrix: List[List[float]]) -> List[Tuple[int, int]]:
    """Solve minimum-weight bipartite matching using Kuhn-Munkres / Jonker-Volgenant algorithm.
    
    Accepts rectangular cost matrix of size (m x n).
    Returns list of optimal (row_idx, col_idx) pairs sorted by row_idx.
    """
    if not cost_matrix or not cost_matrix[0]:
        return []

    n_rows = len(cost_matrix)
    n_cols = len(cost_matrix[0])
    dim = max(n_rows, n_cols)

    # Pad rectangular matrix to square with max possible cost
    max_val = 0.0
    for r in range(n_rows):
        for c in range(n_cols):
            if cost_matrix[r][c] > max_val:
                max_val = cost_matrix[r][c]
    pad_cost = max_val + 10.0

    cost = [[pad_cost] * dim for _ in range(dim)]
    for r in range(n_rows):
        for c in range(n_cols):
            cost[r][c] = cost_matrix[r][c]

    # 1-indexed potential arrays
    u = [0.0] * (dim + 1)
    v = [0.0] * (dim + 1)
    p = [0] * (dim + 1)
    way = [0] * (dim + 1)

    for i in range(1, dim + 1):
        p[0] = i
        j0 = 0
        minv = [float("inf")] * (dim + 1)
        used = [False] * (dim + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = float("inf")
            j1 = 0
            for j in range(1, dim + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j] = cur
                        way[j] = j0
                    if minv[j] < delta:
                        delta = minv[j]
                        j1 = j
            for j in range(dim + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break

    assignments: List[Tuple[int, int]] = []
    for j in range(1, dim + 1):
        if p[j] != 0:
            r = p[j] - 1
            c = j - 1
            if r < n_rows and c < n_cols:
                assignments.append((r, c))

    assignments.sort(key=lambda x: x[0])
    return assignments


def match_detections(
    cand_boxes: List[DetectionOutput],
    base_boxes: List[DetectionOutput],
    iou_cost_threshold: float = 0.95,
) -> Dict[str, Any]:
    """Compute optimal bipartite matching and correspondence metrics between two detection sets.
    
    Returns structured dictionary with:
    - matched_count: int
    - mean_matched_iou: float
    - class_agreement_rate: float
    - mean_coord_delta: float
    - unmatched_cand_count: int
    - unmatched_base_count: int
    - matched_pairs: list of (cand_idx, base_idx, iou)
    """
    if not cand_boxes and not base_boxes:
        return {
            "matched_count": 0,
            "mean_matched_iou": 1.0,
            "class_agreement_rate": 1.0,
            "mean_coord_delta": 0.0,
            "unmatched_cand_count": 0,
            "unmatched_base_count": 0,
            "matched_pairs": [],
        }

    if not cand_boxes or not base_boxes:
        return {
            "matched_count": 0,
            "mean_matched_iou": 0.0,
            "class_agreement_rate": 0.0,
            "mean_coord_delta": 1.0,
            "unmatched_cand_count": len(cand_boxes),
            "unmatched_base_count": len(base_boxes),
            "matched_pairs": [],
        }

    # Construct cost matrix C_ij = 1.0 - IoU(B_cand, B_base)
    n_cand = len(cand_boxes)
    n_base = len(base_boxes)
    cost_matrix = [[0.0] * n_base for _ in range(n_cand)]
    iou_matrix = [[0.0] * n_base for _ in range(n_cand)]

    for i, cb in enumerate(cand_boxes):
        for j, bb in enumerate(base_boxes):
            iou = compute_iou(cb.bbox, bb.bbox)
            iou_matrix[i][j] = iou
            cost_matrix[i][j] = 1.0 - iou

    raw_matches = hungarian_match(cost_matrix)

    matched_pairs: List[Tuple[int, int, float]] = []
    total_iou = 0.0
    matching_classes = 0
    total_coord_delta = 0.0

    matched_cand_indices = set()
    matched_base_indices = set()

    for i, j in raw_matches:
        iou = iou_matrix[i][j]
        # Only accept match if IoU is positive or cost below threshold
        if (1.0 - iou) <= iou_cost_threshold:
            matched_pairs.append((i, j, iou))
            matched_cand_indices.add(i)
            matched_base_indices.add(j)
            total_iou += iou

            cb = cand_boxes[i]
            bb = base_boxes[j]
            if cb.class_id == bb.class_id:
                matching_classes += 1

            # Bounding box deltas in [x_c, y_c, w, h]
            c_xc = (cb.bbox[0] + cb.bbox[2]) / 2.0
            c_yc = (cb.bbox[1] + cb.bbox[3]) / 2.0
            c_w = cb.bbox[2] - cb.bbox[0]
            c_h = cb.bbox[3] - cb.bbox[1]

            b_xc = (bb.bbox[0] + bb.bbox[2]) / 2.0
            b_yc = (bb.bbox[1] + bb.bbox[3]) / 2.0
            b_w = bb.bbox[2] - bb.bbox[0]
            b_h = bb.bbox[3] - bb.bbox[1]

            delta = abs(c_xc - b_xc) + abs(c_yc - b_yc) + abs(c_w - b_w) + abs(c_h - b_h)
            total_coord_delta += delta

    matched_count = len(matched_pairs)
    unmatched_cand_count = n_cand - len(matched_cand_indices)
    unmatched_base_count = n_base - len(matched_base_indices)

    mean_iou = (total_iou / matched_count) if matched_count > 0 else 0.0
    class_agreement = (matching_classes / matched_count) if matched_count > 0 else 0.0
    mean_coord_delta = (total_coord_delta / (4.0 * matched_count)) if matched_count > 0 else 1.0

    return {
        "matched_count": matched_count,
        "mean_matched_iou": mean_iou,
        "class_agreement_rate": class_agreement,
        "mean_coord_delta": mean_coord_delta,
        "unmatched_cand_count": unmatched_cand_count,
        "unmatched_base_count": unmatched_base_count,
        "matched_pairs": matched_pairs,
    }
