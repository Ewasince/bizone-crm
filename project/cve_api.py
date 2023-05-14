import asyncio
import json
from collections import namedtuple
import logging as log

import aiohttp

from config import config

cve_tuple_fields = ['id',  # cve number
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
                    'elimination']  # Необходимые действия по устранению уязвимости

CveTuple = namedtuple('CveTuple', cve_tuple_fields)

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

            epss_data = None  # TODO: добавить апи на запрос epss
            mentions = None  # TODO: добавить реп на упоминания

            pass
        pass

    cve_all_data = json.loads(cve_data_raw)

    cve_duilder = CveTupleBuilder()
    cve_duilder.build(cve_all_data, epss_data, mentions)

    cve = cve_duilder.get_result()

    return [cve]

    pass


class CveTupleBuilder:
    __result_dict: dict

    def __init__(self):
        self.reset()
        pass

    def reset(self):
        self.__result_dict = {k: None for k in cve_tuple_fields}
        pass

    def build(self, cve_all_data, epss_data, mentions):
        # self.__get_data_from_cve_all_data(cve_all_data)

        len_vulnerabilities = len(cve_all_data['vulnerabilities'])
        assert len_vulnerabilities == 1, f'Invalid count of vulnerabilities, len={len_vulnerabilities}'

        cve_data = cve_all_data['vulnerabilities'][0]['cve']
        self.__get_data_from_cve_data(cve_data)

        self.__result_dict['epss'] = self.parse_epss(epss_data)

        metrics = cve_data['metrics']
        self.__get_data_from_cve_metrics(metrics)

        if 'configurations' in cve_data:
            configurations = cve_data['configurations']
            self.__get_data_from_cve_configurations(configurations)
            pass

        references = cve_data['references']
        self.__get_data_from_cve_refs(references)

        descriptions = cve_data['descriptions']
        self.__get_data_from_cve_description(descriptions)

        self.__result_dict['mentions'] = mentions

        self.__result_dict['elimination'] = 'ne ebu'
        pass

    def __get_data_from_cve_all_data(self, cve_all_data) -> None:
        self.__result_dict['cvss_version'] = cve_all_data['version']
        pass

    def __get_data_from_cve_data(self, cve_data) -> None:
        self.__result_dict['id'] = cve_data['id']
        self.__result_dict['date'] = cve_data['published']
        pass

    def __get_data_from_cve_metrics(self, metrics) -> None:
        if len(metrics) == 0:
            return

        if 'cvssMetricV2' in metrics:
            metric_cvss = metrics['cvssMetricV2'][0]
        elif 'cvssMetricV31' in metrics:
            metric_cvss = metrics['cvssMetricV2'][0]
        else:
            raise
        cvss_data = metric_cvss['cvssData']

        self.__result_dict['score'] = cvss_data['baseScore']
        self.__result_dict['vector'] = cvss_data['accessVector']
        self.__result_dict['complexity'] = cvss_data['accessComplexity']
        pass

        if 'cvssMetricV2' in metrics \
                and len(metrics['cvssMetricV2']):
            cvss_metrics_v2_list = metrics['cvssMetricV2']
            cvss_metrics_v2 = cvss_metrics_v2_list[0]
            cvss_data_v2 = cvss_metrics_v2['cvssData']
            if 'baseSeverity' in cvss_data_v2:
                base_severity_v2 = cvss_data_v2['baseSeverity']
                self.__result_dict['cvss31'] = base_severity_v2
                pass

            pass

        if 'cvssMetricV31' in metrics \
                and len(metrics['cvssMetricV31']):
            cvss_metrics_v31_list = metrics['cvssMetricV31']
            cvss_metrics_v31 = cvss_metrics_v31_list[0]
            cvss_data_v31 = cvss_metrics_v31['cvssData']
            if 'baseSeverity' in cvss_data_v31:
                base_severity_v31 = cvss_data_v31['baseSeverity']
                self.__result_dict['cvss31'] = base_severity_v31
                pass
            pass
        pass

    def __get_data_from_cve_configurations(self, configurations) -> None:
        products_names = []
        product_versions = []
        for conf in configurations:
            for node in conf['nodes']:
                product = node['cpeMatch'][0]
                if product['vulnerable']:
                    criteria = product['criteria'].split(':')
                    product_name = criteria[4]
                    if 'versionEndIncluding' in product:
                        product_version = product['versionEndIncluding']
                    else:
                        product_version = criteria[5]
                        pass
                    products_names.append(product_name)
                    product_versions.append(product_version)
                    pass  # -- if
                pass  # -- for
            pass  # -- for

        self.__result_dict['product'] = '\n'.join(products_names)
        self.__result_dict['versions'] = '\n'.join(product_versions)
        pass

    def __get_data_from_cve_refs(self, references) -> None:
        references_urls = []
        for ref in references:
            url = ref['url']
            references_urls.append(url)
            pass

        self.__result_dict['poc'] = '\n'.join(references_urls)
        pass

    def __get_data_from_cve_description(self, descriptions) -> None:
        for description in descriptions:
            if description['lang'] == 'ru':
                self.__result_dict['description'] = description['value']
                break
            elif description['lang'] == 'en':
                self.__result_dict['description'] = description['value']
                break
                pass  # --elif
            pass  # --for
        else:  # when there is no suitable language
            self.__result_dict['description'] = descriptions[0]['value']
            pass
        pass

    def parse_epss(self, epss_data) -> str:
        log.warning(f'[CveTupleBuilder] [parse_epss] not implemented yet!')
        return None

    def find_mentions(self, cve_id: str) -> str:
        log.warning(f'[CveTupleBuilder] [find_mentions] not implemented yet!')
        return None

    def get_result(self) -> CveTuple:
        return CveTuple(**self.__result_dict)


if __name__ == '__main__':
    test_cve_id = 'CVE-2019-1010218'


    # test_cve_id = 'CVE-2017-0144'
    # test_cve_id = 'CVE-2022-42889'

    async def test_func():
        res = await aget_cve_by_number(test_cve_id)
        pass


    asyncio.run(test_func())