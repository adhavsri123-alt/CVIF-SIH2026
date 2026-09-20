"""Feature extraction package for CVIF."""

from cvif.features.base import FeatureExtractor, MockFeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor

__all__ = ["FeatureExtractor", "MockFeatureExtractor", "StatisticalFeatureExtractor"]
