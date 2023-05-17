from typing import List
import logging as log

from api.builders.cve_builder import Cve
from api.epss_api.epss_api import EpssApi


class EpssBuilder:

    def __init__(self, epss_api: EpssApi):
        self.__epss_api = epss_api
        pass

    async def a_bunch_add_epss(self, cves: List[Cve]):
        """
        Получает и добавляет очки epss к существующему списку CVE

        :param cves:
        :return:
        """
        try:
            cve_id_list = []
            for cve in cves:
                cve_id_list.append(cve.id)
                pass

            epss_scores = await self.__epss_api.a_get_epss_api(cve_id_list)

            for cve, epss in zip(cves, epss_scores):
                cve.epss = epss
                pass
        except Exception as e:
            log.warning(f'[EpssBuilder] [a_bunch_add_epss] error get epss, e={e}')
            pass

        return cves

    pass
