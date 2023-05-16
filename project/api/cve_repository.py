import logging as log
from typing import Optional, List, Tuple

from api.builders.cve_builder import Cve
from api.builders.epss_builder import EpssBuilder
from api.builders.translate_builder import TranslateBuilder
from api.builders.trends_cve_builder import CveTrendsTuple
from api.nist_api.nist_api import NistApi
from api.trends_api.trends_api import TrendsApi
from config import config


class CveRepository:

    def __init__(self,
                 nist_api: NistApi,
                 translate_builder: TranslateBuilder,
                 trends_api: TrendsApi,
                 epss_api: EpssBuilder):
        self.__nist_api: NistApi = nist_api
        self.__translate_builder: TranslateBuilder = translate_builder
        self.__trends_api: TrendsApi = trends_api
        self.__epss_api = epss_api
        pass

    async def a_get_cve_by_id(self, cve_id: str) -> List[Cve]:
        """
        returns a list of Cve by passed cve id
        """

        try:

            self.__nist_api.set_id_param(cve_id)

            cves_list = await self.__nist_api.a_execute_request()
            cves_list = await self.prepare_cves(cves_list)

            return cves_list
        except Exception as e:
            log.error(f'[a_get_cve_by_id] FAIL, e={e}')
            raise Exception(f'exception in a_get_cve_by_id, e={e}')

    async def a_get_cve_by_params(self,
                                  cvss: Optional[List[str]],
                                  qm: Optional[None],
                                  vector: Optional[List[str]],
                                  complexity: Optional[List[str]],
                                  epss: Optional[Tuple[float, float]],
                                  date: Optional[Tuple[str, str]],
                                  product: Optional[str],
                                  vendor: Optional[str],
                                  mentions: Optional[Tuple[float, float]]
                                  ) -> List[Cve]:
        """
        Принимает на вход критерии поиска и выдаёт cve по этим критериям. Если вместо критерия передано None, критерий
        при поиске не учитывается


        :param self:
        :param cvss: список из уровней опасности, пример: ['HIGH', 'LOW'] ['MEDIUM']
        :param qm: пока пустой параметр
        :param vector: список векторов атаки, пример: ['NETWORK', 'LOCAL'], ['ADJACENT NETWORK']
        :param complexity: сложность применения уязвимости, пример: ['HIGH', 'LOW'] ['MEDIUM']
        :param epss: вероятность применения хацкерами данной уязвимости. передается как кортеж из нижнего и верхнего
        диапазона. Если граница диапазона отсутствует, то передаётся None. Пример: (1.0, 5.0), (8.0, None)
        :param date: Дата публикации cve. Передаётся кортеж, содержащий верхний и нижний предел. Если граница отсутствует,
        передаётся None. Пример: (datetime(2022,01,01, None)
        :param product: Наименование продукта. Пример: windows_10
        :param vendor: Наименование издателя. Пример: microsoft
        :param mentions: Количество упоминаний. Если граница отсутствует, передаётся None. Пример: (228, 1337), (42, None)
        :return:
        """

        try:
            nist_api = self.__nist_api

            # if any(map(lambda x: x is not None, cvss)):
            if cvss is not None:
                nist_api.set_severity_param(cvss)
                pass

            # if any(map(lambda x: x is not None, vector)):
            if vector is not None:
                nist_api.set_vector_param(vector)
                pass

            # if any(map(lambda x: x is not None, complexity)):
            if complexity is not None:
                nist_api.set_complexity_param(complexity)
                pass

            # if any(map(lambda x: x is not None, epss)):
            if epss is not None:
                nist_api.set_epss_param(epss)
                pass

            if any(map(lambda x: x is not None, date)):
                nist_api.set_date_param(date)
                pass

            if product is not None:
                nist_api.set_product_param(product)
                pass

            if vendor is not None:
                nist_api.set_vendor_param(vendor)
                pass

            # if any(map(lambda x: x is not None, mentions)):
            if mentions is not None:
                nist_api.set_mentions_param(mentions)
                pass

            cves_list = await self.__nist_api.a_execute_request()
            cves_list = await self.prepare_cves(cves_list)

            return cves_list
        except Exception as e:
            log.error(f'[a_get_cve_by_id] FAIL, e={e}')
            raise Exception(f'exception in a_get_cve_by_params, e={e}')

    async def a_get_trends_cve(self, period: str):
        """
            Выдаёт самые пополярные CVE за последний промежуток {__period} времени
        """

        try:
            trends_api = self.__trends_api
            trends_api.set_url(period)

            cves_list: List[CveTrendsTuple] = await trends_api.a_execute_request()
            cves_list = await self.prepare_cves(cves_list)

            return cves_list
        except Exception as e:
            log.error(f'[a_get_trends_cve] FAIL, e={e}')
            raise Exception(f'exception in a_get_trends_cve, e={e}')
        pass

    async def prepare_cves(self, cves_list):
        if config.translate_descriptions:
            cves_list = await self.__translate_builder.a_bunch_translate(cves_list)
            pass

        if config.add_epss:
            cves_list = await self.__epss_api.a_bunch_add_epss(cves_list)
            pass


        return cves_list
