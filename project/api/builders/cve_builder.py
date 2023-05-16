import logging as log
from collections import namedtuple
from typing import Optional, List

from api.nist_api.cvss_enum import CvssVerEnum

cve_tuple_fields = ['id',  # cve id
                    'link',  # ссылка на CVE
                    'cvss2',  # CVSS 2 рейтинг 
                    'cvss3',  # CVSS 3.1 рейтинг
                    'score',  # Уровень критичности
                    'vector',  # Уровень критичности
                    'complexity',  # Уровень критичности
                    'epss',  # EPSS рейтинг
                    'date',  # Дата/время регистрации CVE
                    'product',  # Продукт/вендор для которого характерна CVE
                    'versions',  # Уязвимые версии продукта
                    'poc',  # PoC/CVE WriteUp (С кликабельными ссылками, если есть) ЭТО НЕ ПОКИ думаю Переименновать в полезные ссылки
                    'description',  # Описание CVE
                    'mentions',  # Информация о количестве упоминаний о CVE УБРАТЬ 
                    'elimination']  # Необходимые действия по устранению уязвимости

CveTuple = namedtuple('CveTuple', cve_tuple_fields)


class CveTupleBuilder:

    def __init__(self):
        self.__resul_cves: Optional[List[CveTuple]] = []
        self.__result_dict: dict
        self.reset()
        pass

    def reset(self):
        self.__result_dict = {k: None for k in cve_tuple_fields}
        self.__resul_cves = []
        pass

    def build(self, cve_all_data, epss_data, mentions):
        # self.__get_data_from_cve_all_data(cve_all_data)

        # len_vulnerabilities = len(cve_all_data['vulnerabilities'])
        # assert len_vulnerabilities == 1, f'Invalid count of vulnerabilities, len={len_vulnerabilities}'

        for vulnerability in cve_all_data['vulnerabilities']:

            cve_data = vulnerability['cve']
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

            self.__result_dict['elimination'] = None

            self.__resul_cves.append(CveTuple(**self.__result_dict))
            pass

        pass

    def __get_data_from_cve_all_data(self, cve_all_data) -> None:
        self.__result_dict['cvss_version'] = cve_all_data['version']
        pass

    def __get_data_from_cve_data(self, cve_data) -> None:
        cve_id: str = cve_data['id']
        self.__result_dict['id'] = cve_id
        self.__result_dict['date'] = cve_data['published']

        self.__result_dict['link'] = f'https://nvd.nist.gov/vuln/detail/{cve_id.upper()}'
        pass

    def __get_data_from_cve_metrics(self, metrics) -> None:
        if len(metrics) == 0:
            return

        if 'cvssMetricV2' in metrics:
            metric_cvss = metrics['cvssMetricV2'][0]
        elif 'cvssMetricV30' in metrics:
            metric_cvss = metrics['cvssMetricV30'][0]
        elif 'cvssMetricV31' in metrics:
            metric_cvss = metrics['cvssMetricV31'][0]
        else:
            raise
        cvss_data = metric_cvss['cvssData']

        self.__result_dict['score'] = cvss_data['baseScore']

        if 'accessVector' in cvss_data:
            self.__result_dict['vector'] = cvss_data['accessVector']
        elif 'attackVector' in cvss_data:
            self.__result_dict['vector'] = cvss_data['attackVector']
            pass

        if 'accessComplexity' in cvss_data:
            self.__result_dict['complexity'] = cvss_data['accessComplexity']
        elif 'attackComplexity' in cvss_data:
            self.__result_dict['complexity'] = cvss_data['attackComplexity']
            pass
        pass

        score = float(self.__result_dict['score'])

        if 'cvssMetricV2' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics['cvssMetricV2'], CvssVerEnum.VER2.value, score)
            pass

        if 'cvssMetricV30' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics['cvssMetricV30'], CvssVerEnum.VER3.value, score)
            pass
        elif 'cvssMetricV31' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics['cvssMetricV31'], CvssVerEnum.VER31.value, score)
            pass

        pass

    def __get_cvss_from_cvss_metrics(self, metrics_list, version: str, score: float) -> None:
        cvss_metrics = metrics_list[0]
        cvss_data = cvss_metrics['cvssData']
        if 'baseSeverity' in cvss_data:
            base_severity = cvss_data['baseSeverity']
            pass
        else:
            match version:
                case CvssVerEnum.VER2.value:
                    base_severity = self.__get_severity_v2(score)
                case CvssVerEnum.VER3.value:
                    base_severity = self.__get_severity_v3(score)
                case _:
                    base_severity = self.__get_severity_v3(score)
            pass

        # save cvss severity
        match version:
            case CvssVerEnum.VER2.value:
                self.__result_dict['cvss2'] = base_severity
                pass
            case CvssVerEnum.VER3.value:
                self.__result_dict['cvss3'] = base_severity
                pass
            case _:
                self.__result_dict['cvss3'] = base_severity
                pass
        pass

    def __get_severity_v2(self, score) -> str:
        if score < 4.0:
            return 'LOW'
        elif 4.0 <= score < 7.0:
            return 'MEDIUM'
        elif 7.0 <= score:
            return 'HIGH'

    def __get_severity_v3(self, score) -> str:
        if score < 4.0:
            return 'LOW'
        elif 4.0 <= score < 7.0:
            return 'MEDIUM'
        elif 7.0 <= score < 9.0:
            return 'HIGH'
        elif 9.0 <= score:
            return 'CRITICAL'

    def __get_data_from_cve_configurations(self, configurations) -> None:
        products_names = []
        product_versions = []
        for conf in configurations:
            for node in conf['nodes']:
                for cpe_match in node['cpeMatch']:
                    product = cpe_match
                    # if not product['vulnerable']:
                    #     continue
                    #     pass

                    criteria = product['criteria'].split(':')
                    product_name = criteria[4]
                    if 'versionEndIncluding' in product:
                        product_version = 'меньше, чем ' + product['versionEndIncluding']
                    else:
                        product_version = criteria[5]
                        pass
                    products_names.append(product_name)
                    product_versions.append(product_version)
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

    def get_result(self) -> List[CveTuple]:
        return self.__resul_cves
