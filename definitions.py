from enum import Enum


class RRule(Enum):
    """
    Define rule relations
    """
    IMB = 5  # "IMB"  # Inclusive match (subset)   包含匹配（子集）
    IMP = 4  # "IMP"  # Inclusive match (superset) 包含匹配（超集）
    CC = 3  # "CC"  # corrolation       相关
    EM = 2  # "EM"  # exact match       完全匹配
    PD = 1  # "PD"  # partial disjoint  部分不相交
    CD = 0  # "CD"  # complete disjoint 完全不相交

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class RField(Enum):
    """
    Define field relations
    """
    UNEQUAL = 0
    EQUAL = 1
    SUBSET = 2
    SUPERSET = 3

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Anomaly(Enum):
    """
    Define anomaly types
    """
    AOK = 0  # no anomaly
    SHD = 1  # shadowing
    COR = 2  # corrolation
    RYD = 3  # redundancy: x is a superset of y
    RXD = 4  # redundancy: x is a supset of y
    GEN = 5  # generalization

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name
