from api.nist_api.cvss_enum import CvssVerEnum
from api.nist_api.nist_api import NistApi
from api.nist_api.nist_api_cvss2 import NistApiCvss2
from api.nist_api.nist_api_cvss3 import NistApiCvss3


class NistApiFactory:

    # @staticmethod
    # def get_instance(ver) -> NistApi:
    #     match ver:
    #         case CvssVerEnum.VER2.value:
    #             return NistApiCvss2()
    #         case CvssVerEnum.VER3.value:
    #             return NistApiCvss3()
    #         case _:
    #             return NistApiCvss3()

    @staticmethod
    def get_instance(ver) -> NistApi:
        match ver:
            case CvssVerEnum.VER2.value:
                return NistApi('cvssV2Severity',
                               'cvssV2Metrics',
                               ['LOW', 'MEDIUM', 'HIGH'])
            case CvssVerEnum.VER3.value:
                return NistApi('cvssV3Severity',
                               'cvssV3Metrics',
                               ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
            case _:
                return NistApi('cvssV3Severity',
                               'cvssV3Metrics',
                               ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
