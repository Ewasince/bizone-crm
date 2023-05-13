import asyncio
import json
from collections import namedtuple
import logging as log

import aiohttp

from config import config

CveTuple = namedtuple('CveTuple',
                      ['id',  # cve number
                       'cvss2',  # CVSS 2 рейтинг
                       'cvss31',  # CVSS 3.1 рейтинг
                       'score',  # Уровень критичности
                       'vector',  # Уровень критичности
                       'complexity',  # Уровень критичности
                       'epss',  # EPSS рейтинг
                       'date',  # Дата/время регистрации CVE
                       'product',  # Продукт/вендор для которого характерна CVE
                       'versions',  # Уязвимые версии продукта
                       'poc',  # PoC/CVE WriteUp (С кликабельными ссылками, если есть)
                       'description',  # Описание CVE
                       'mentions',  # Информация о количестве упоминаний о CVE
                       'elimination',  # Необходимые действия по устранению уязвимости
                       'cvss_version']  # версия cvss
                      )

api_url = config.cve_api + config.cve_api_version


async def aget_cve_by_number(cve_id: str) -> [CveTuple]:
    """
    returns a list of CveTuple by passed cve id
    """
    # example: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218

    api_url_with_id = f'{api_url}?cveId={cve_id}'
    # api_url_with_id = 'https://ya.ru'

    async with aiohttp.ClientSession() as session:
        async with session.get(api_url_with_id) as resp:  # открытие сессии в aiohttp

            if resp.status != 200:
                log.warning(f"[aget_cve_by_number] cannot get url={api_url_with_id}, status_code={resp.status}")
                raise Exception('Response error')

            cve_data_raw = await resp.text()
            pass
        pass

    cve_data = json.loads(cve_data_raw)

    cve = pasre_cve_response(cve_data)

    return [cve]

    pass


def pasre_cve_response(cve_all_data: dict) -> CveTuple:
    len_vulnerabilities = len(cve_all_data['vulnerabilities'])
    assert len_vulnerabilities == 1, f'Invalid count of vulnerabilities, len={len_vulnerabilities}'

    cve_data = cve_all_data['vulnerabilities'][0]['cve']

    cve_duilder = CveTupleBuilder()
    cve_duilder.build(cve_data, None)

    ccve_tuple = cve_duilder.get_result()

    return ccve_tuple


async def aget_parametrized_cve() -> [CveTuple]:
    pass


class CveTupleBuilder:
    __result: CveTuple

    def __init__(self):
        self.reset()
        pass

    def reset(self):
        self.__result = CveTuple(*[None] * 15)
        pass

    def build(self, cve_data, epss_data):
        cve_dict = {}

        cve_dict['id'] = cve_data['id']

        if 'cvssMetricV2' in cve_data or \
                'cvssMetricV3' in cve_data or \
                'cvssMetricV31' in cve_data:
            # FIXME узнать какие бывают версии cvss у этого api
            metric_cvss = iter(cve_data['metrics']).pop()
            cvss_data = metric_cvss['cvssData']

            cve_dict['score'] = metric_cvss['baseScore']
            cve_dict['vector'] = cvss_data['accessVector']
            cve_dict['complexity'] = cvss_data['accessComplexity']
            pass

        if 'cvssMetricV2' in cve_data:
            metric_cvss_v2 = cve_data['metrics']['cvssMetricV2'].pop()['baseSeverity']
            cve_dict['cvss2'] = metric_cvss_v2
            pass

        if 'cvssMetricV31' in cve_data:
            metric_cvss_v31 = cve_data['metrics']['cvssMetricV31'].pop()['baseSeverity']
            cve_dict['cvss31'] = metric_cvss_v31
            pass

        cve_dict['epss'] = self.parse_epss(epss_data)

        cve_dict['date'] = cve_data['published']


        # cve_dict['product'] =
        # cve_dict['versions'] =
        # cve_dict['poc'] =
        # cve_dict['description'] =
        # cve_dict['mentions'] =
        # cve_dict['elimination'] =
        # cve_dict['cvss_version'] = cve_all_data['version']

        pass

    def parse_epss(self, epss_data) -> str:
        log.warning(f'[CveTupleBuilder] [parse_epss] not implemented yet!')
        return None

    def get_result(self) -> CveTuple:
        return self.__result


if __name__ == '__main__':
    test_cve_id = 'CVE-2019-1010218'


    async def test_func():
        res = await aget_cve_by_number(test_cve_id)
        pass


    asyncio.run(test_func())
