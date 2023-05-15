from typing import List

from api.nist_api.nist_api import NistApi


class NistApiCvss2(NistApi):

    def __init__(self):
        super().__init__()
        self.__severity_cvss_param_name = 'cvssV2Severity'
        self.__metrics_cvss_param_name = 'cvssV2Metrics'
        self.__severity: List[str] = ['LOW', 'MEDIUM', 'HIGH']
        pass
