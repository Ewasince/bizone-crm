from enum import Enum

from aiohttp.web_routedef import static


class CvssVerEnum(Enum):
    VER2 = '2'
    VER3 = '3'
    VER31 = '31'

    @staticmethod
    def get_values():
        return [e.value for e in CvssVerEnum]
