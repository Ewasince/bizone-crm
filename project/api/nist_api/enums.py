from enum import Enum

from aiohttp.web_routedef import static


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
    LOCAL = 'Local'
    ADJACENT_NETWORK = 'Adjacent Network'
    NETWORK = 'Network'
    pass


class ComplexityEnum(GetValuesEnum, Enum):
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    pass
