from dataclasses import dataclass, fields
from dataclasses import dataclass, fields
from typing import Optional, List

from api.nist_api.enums import CvssSeverityV2Enum, CvssSeverityV3Enum


@dataclass
class Cve:
    '''
    Класс, представляющий объект CVE
    '''

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
        '''
        Фукнция, возвращающая список имен всех полей

        :return:
        '''
        return [f.name for f in fields(Cve)]

    pass


class CveTupleBuilder:
    '''
    Клас, создающий CVE из сырых данных json
    '''

    def __init__(self):
        self.__resul_cves: Optional[List[Cve]] = []
        self.__result_dict: dict = {}
        self.reset()
        pass

    def reset(self):
        """
        Сбрасывает состояние билдера

        :return:
        """
        self.__result_dict = {k: None for k in Cve.get_fields()}
        self.__resul_cves = []
        pass

    def build(self, cve_all_data):
        """
        Создаёт список CVE из переданного объекта json

        :param cve_all_data:
        :return:
        """

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
        """
        Получает версию CVSS

        :param cve_all_data:
        :return:
        """
        self.__result_dict['cvss_version'] = cve_all_data['version']
        pass

    def __get_data_from_cve_data(self, cve_data) -> None:
        """
        Получает дату и id cve, а так же создаёт ссылку на него

        :param cve_data:
        :return:
        """
        cve_id: str = cve_data['id']
        self.__result_dict['id'] = cve_id
        self.__result_dict['date'] = cve_data['published']

        self.__result_dict['link'] = f'https://nvd.nist.gov/vuln/detail/{cve_id.upper()}'
        pass

    def __set_vector(self, vector):
        """
        Устанавливает вектор атаки

        :param vector:
        :return:
        """
        self.__result_dict['vector'] = vector
        pass

    def __set_complexity(self, complexity):
        """
        Устанавливает сложность применения атаки

        :param complexity:
        :return:
        """
        self.__result_dict['complexity'] = complexity
        pass

    def __get_data_from_cve_metrics(self, metrics) -> None:
        """
        Устанавливает уровень опасности CVE для CVSS v2 и v3
        Так же устанавливает вектор и сложность

        :param metrics:
        :return:
        """
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

    def __get_cvss_from_cvss_metrics(self, metrics, ver: str) -> None:
        """
        Вспомогательная функция, заполняет данные о уровне критичность CVE

        :param metrics:
        :param ver:  Версия CVSS, пример: '2', '31'
        :return:
        """
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
                score_func = self.__get_severity_v3
            case '31':
                metrics_name = 'cvssMetricV31'
                score_name = 'score_v3'
                cvss_name = 'cvss3'
                score_func = self.__get_severity_v3
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
        """
        Вспомогательная функция выдаёт уровень опасности CVE по уровню score

        :param score:
        :return:
        """

        if score < 4.0:
            return CvssSeverityV2Enum.LOW.value
        elif 4.0 <= score < 7.0:
            return CvssSeverityV2Enum.MEDIUM.value
        elif 7.0 <= score:
            return CvssSeverityV2Enum.HIGH.value

    def __get_severity_v3(self, score) -> str:
        """
        Вспомогательная функция выдаёт уровень опасности CVE по уровню score

        :param score:
        :return:
        """

        if score < 4.0:
            return CvssSeverityV3Enum.LOW.value
        elif 4.0 <= score < 7.0:
            return CvssSeverityV3Enum.MEDIUM.value
        elif 7.0 <= score < 9.0:
            return CvssSeverityV3Enum.HIGH.value
        elif 9.0 <= score:
            return CvssSeverityV3Enum.CRITICAL.value

    def __get_data_from_cve_configurations(self, configurations) -> None:
        """
        Устанавливает уязвимые продукты и их версии

        :param configurations:
        :return:
        """
        product_vesions_names = set()
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

                    product_vesions_names.add((product_name, product_version))
                    # products_names.add(product_name)
                    # product_versions.add(product_version)
                pass  # -- for
            pass  # -- for

        products_names = []
        product_versions = []

        for n, v in product_vesions_names:
            products_names.append(n)
            product_versions.append(v)
            pass

        self.__result_dict['product'] = '\n'.join(products_names)
        self.__result_dict['versions'] = '\n'.join(product_versions)
        pass

    def __get_data_from_cve_refs(self, references) -> None:
        """
        Устанавливает упоминания на CVE

        :param references:
        :return:
        """
        references_urls = []
        for ref in references:
            url = ref['url']
            references_urls.append(url)
            pass

        self.__result_dict['mentions'] = references_urls
        pass

    def __get_data_from_cve_description(self, descriptions) -> None:
        """
        Устанавливает описание CVE

        :param descriptions:
        :return:
        """
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

    def get_result(self) -> List[Cve]:
        """
        Выдаёт итоговый список CVE

        :return:
        """
        return self.__resul_cves
