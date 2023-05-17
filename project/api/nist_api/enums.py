from enum import Enum

"""
Файл со всеми перечислениями
"""


class CvssVerEnum(Enum):
    VER2 = '2'
    VER3 = '3'
    VER31 = '31'

    @staticmethod
    def get_values():
        return [e.value for e in CvssVerEnum]


class GetValuesEnum(Enum):

    @classmethod
    def get_values(cls):
        return [e.value for e in cls]

    pass


class CvssSeverityV2Enum(GetValuesEnum, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    pass


class CvssSeverityV3Enum(GetValuesEnum, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'
    pass


class VectorsEnum(GetValuesEnum, Enum):
    LOCAL = 'LOCAL'
    ADJACENT_NETWORK = 'ADJACENT NETWORK'
    NETWORK = 'NETWORK'
    pass


class ComplexityEnum(GetValuesEnum, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    pass
