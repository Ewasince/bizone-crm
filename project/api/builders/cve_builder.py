import logging as log
from dataclasses import dataclass, fields
from typing import Optional, List

from api.nist_api.enums import CvssVerEnum, VectorsEnumPresent, ComplexityEnum, CvssSeverityV2Enum, CvssSeverityV3Enum


@dataclass
class Cve:
    id: str
    link: Optional[str]
    vector: Optional[str]
    complexity: Optional[str]
    epss: Optional[str]
    date: Optional[str]
    product: Optional[str]
    versions: Optional[str]
    poc: Optional[str]
    description: Optional[str]
    mentions: Optional[str]
    elimination: Optional[str]

    cvss2: Optional[str] = None
    cvss3: Optional[str] = None
    score_v2: Optional[str] = None
    score_v3: Optional[str] = None

    @staticmethod
    def get_fields():
        return [f.name for f in fields(Cve)]

    pass


class CveTupleBuilder:

    def __init__(self):
        self.__resul_cves: Optional[List[Cve]] = []
        self.__result_dict: dict = {}
        self.reset()
        pass

    def reset(self):
        self.__result_dict = {k: None for k in Cve.get_fields()}
        self.__resul_cves = []
        pass

    def build(self, cve_all_data):
        for vulnerability in cve_all_data['vulnerabilities']:

            cve_data = vulnerability['cve']
            self.__get_data_from_cve_data(cve_data)

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

            self.__result_dict['poc'] = None
            self.__result_dict['epss'] = None
            self.__result_dict['elimination'] = None

            self.__resul_cves.append(Cve(**self.__result_dict))
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

    def __set_vector(self, vector):
        self.__result_dict['vector'] = vector
        pass

    def __set_complexity(self, complexity):
        self.__result_dict['complexity'] = complexity
        pass

    def __get_data_from_cve_metrics(self, metrics) -> None:
        if len(metrics) == 0:
            return

        if 'cvssMetricV2' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics, '2')
            pass
        if 'cvssMetricV30' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics, '3')
            pass
        if 'cvssMetricV31' in metrics:
            self.__get_cvss_from_cvss_metrics(metrics, '31')

        # выбираем по какому cvss будем показывать метрики
        if 'cvssMetricV2' in metrics:
            metric_cvss = metrics['cvssMetricV2'][0]
        elif 'cvssMetricV30' in metrics:
            metric_cvss = metrics['cvssMetricV30'][0]
        elif 'cvssMetricV31' in metrics:
            metric_cvss = metrics['cvssMetricV31'][0]
        else:
            raise Exception('Invalid cvss ver')
        cvss_data = metric_cvss['cvssData']

        # устанавливаем вектор атаки
        if 'accessVector' in cvss_data:
            vector = cvss_data['accessVector']
            self.__set_vector(vector)
        elif 'attackVector' in cvss_data:
            vector = cvss_data['attackVector']
            self.__set_vector(vector)
            pass

        # устанавливаем сложность
        if 'accessComplexity' in cvss_data:
            complexity = cvss_data['accessComplexity']
            self.__set_complexity(complexity)
        elif 'attackComplexity' in cvss_data:
            complexity = cvss_data['attackComplexity']
            self.__set_complexity(complexity)
            pass

        pass

        # if 'cvssMetricV2' in metrics:
        #     pass
        # 
        # if 'cvssMetricV30' in metrics:
        #     self.__get_cvss_from_cvss_metrics(metrics['cvssMetricV30'], CvssVerEnum.VER3.value, score)
        #     pass
        # 
        # elif 'cvssMetricV31' in metrics:
        #     self.__get_cvss_from_cvss_metrics(metrics['cvssMetricV31'], CvssVerEnum.VER31.value, score)
        #     pass

        pass

    def __get_cvss_from_cvss_metrics(self, metrics, ver: str) -> None:
        match ver:
            case '2':
                metrics_name = 'cvssMetricV2'
                score_name = 'score_v2'
                cvss_name = 'cvss2'
                score_func = self.__get_severity_v2
            case '3':
                metrics_name = 'cvssMetricV30'
                score_name = 'score_v3'
                cvss_name = 'cvss3'
                score_func = self.__get_severity_v2
            case '31':
                metrics_name = 'cvssMetricV31'
                score_name = 'score_v3'
                cvss_name = 'cvss3'
                score_func = self.__get_severity_v2
            case _:
                raise Exception('Wrong ver name')

        metric_cvss = metrics[metrics_name][0]
        cvss_data = metric_cvss['cvssData']
            
        # устанавливаем оценку опасности
        score = cvss_data['baseScore']
                
        self.__result_dict[score_name] = score

        base_severity = score_func(float(score))
        self.__result_dict[cvss_name] = base_severity
        pass

    def __get_severity_v2(self, score) -> str:
        if score < 4.0:
            return CvssSeverityV2Enum.LOW.value
        elif 4.0 <= score < 7.0:
            return CvssSeverityV2Enum.MEDIUM.value
        elif 7.0 <= score:
            return CvssSeverityV2Enum.HIGH.value

    def __get_severity_v3(self, score) -> str:
        if score < 4.0:
            return CvssSeverityV3Enum.LOW.value
        elif 4.0 <= score < 7.0:
            return CvssSeverityV3Enum.MEDIUM.value
        elif 7.0 <= score < 9.0:
            return CvssSeverityV3Enum.HIGH.value
        elif 9.0 <= score:
            return CvssSeverityV3Enum.CRITICAL.value

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
                        product_version = 'до ' + product['versionEndIncluding']
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

        self.__result_dict['mentions'] = references_urls
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

    def find_mentions(self, cve_id: str) -> str:
        log.warning(f'[CveTupleBuilder] [find_mentions] not implemented yet!')
        return None

    def get_result(self) -> List[Cve]:
        return self.__resul_cves
