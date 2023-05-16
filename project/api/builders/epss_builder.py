from typing import List

from api.builders.cve_builder import Cve
from api.epss_api.epss_api import EpssApi


class EpssBuilder:

    def __init__(self, epss_api: EpssApi):
        self.__epss_api = epss_api
        pass

    async def a_bunch_add_epss(self, cves: List[Cve]):
        cve_id_list = []
        for cve in cves:
            cve_id_list.append(cve.id)
            pass

        epss_scores = await self.__epss_api.a_get_epss_api(cve_id_list)

        for cve, epss in zip(cves, epss_scores):
            cve.epss = epss
            pass

        return cves

    pass
