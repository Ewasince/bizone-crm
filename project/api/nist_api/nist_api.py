import json
import logging as log
from copy import copy
from datetime import datetime, timedelta
from typing import Optional, Tuple, List

import aiohttp
import dateutil.parser as isoparser
from pytz import timezone

from api.builders.cve_builder import CveTupleBuilder, Cve
from api.nist_api.enums import CvssVerEnum, CvssSeverityV2Enum, CvssSeverityV3Enum, VectorsEnumPresent, ComplexityEnum
from config import config


class ParseDateException(ValueError):
    pass


class NistApi:
    VECTORS_ABBR: dict = {
        VectorsEnumPresent.LOCAL.value: 'L',
        VectorsEnumPresent.ADJACENT_NETWORK.value: 'A',
        VectorsEnumPresent.NETWORK.value: 'N',
    }

    COMPLEXITY_ABBR: dict = {
        ComplexityEnum.LOW.value: 'L',
        ComplexityEnum.MEDIUM.value: 'M',
        ComplexityEnum.HIGH.value: 'H',
    }

    def __init__(self,
                 severity_param_name,
                 metric_param_name,
                 severities_list):
        # cvss version params
        self.__severity_cvss_param_name: str = severity_param_name
        self.__metrics_cvss_param_name: str = metric_param_name
        self.__severity: List[str] = severities_list

        # api url
        self.__api_url: str = config.cve_api + config.cve_api_version

        # instance params
        self.__request_url: Optional[List[str]] = None

        self.__id_param: Optional[str] = None
        self.__severity_param: Optional[Tuple[str]] = None
        self.__vector_param: Optional[Tuple[str]] = None
        self.__complexities_param: Optional[Tuple[str]] = None
        self.__epss_param: Optional[Tuple[float, float]] = None
        self.__date_param: Optional[Tuple[datetime]] = None
        self.__product_param: Optional[str] = None
        self._vendor_param: Optional[str] = None
        self.__mentions_param: Optional[Tuple[float, float]] = None

        # user parameters
        self.__timezone: timezone = timezone('Europe/Moscow')

        # reset params
        self.reset_request_url()

    def reset_request_url(self):
        self.__request_url = None

        self.__id_param = None
        self.__severity_param = None

        # self.__params = {}
        pass

    async def a_execute_request(self) -> List[Cve]:
        self.__build_url()
        assert self.__request_url is not None, "No parameters passed to request url"

        cve_datas_raw = []

        async with aiohttp.ClientSession() as session:
            for url in self.__request_url:
                async with session.get(url) as resp:  # открытие сессии в aiohttp
                    log.debug(
                        f"[NistApi] [a_execute_request] url request, url={url}")
                    if resp.status != 200:
                        log.warning(
                            f"[a_execute_request] cannot get url={self.__request_url}, status_code={resp.status}")
                        raise Exception('Response error')

                    cve_data_raw = await resp.text()

                    cve_datas_raw.append(cve_data_raw)
                    pass
            pass

        result_cves = []

        for cve_data_raw in cve_datas_raw:
            cve_all_data = json.loads(cve_data_raw)

            cve_builder = CveTupleBuilder()
            cve_builder.build(cve_all_data)

            cves = cve_builder.get_result()
            result_cves.extend(cves)
            pass

        # epss_data = None  # TODO: добавить апи на запрос epss

        return result_cves

    def __build_url(self):
        """
        Собирает url к api из хранящихся в памяти параметров.

        :return:
        """

        params: dict = self.__prepare_params()

        params_values = [*params.values()]
        params_list = self.recursive_queries(params_values)

        if len(params_list) == 0:
            self.__request_url = None
            return None

        result_urls_list = []

        for params in params_list:
            result_url = self.__api_url + '?'
            result_url += '&'.join(params)
            result_urls_list.append(result_url)
            pass
        self.__request_url = result_urls_list

        pass

    def recursive_queries(self, params: list) -> List[List[str]]:
        if len(params) != 1:
            cur_prams = params.pop()
            refactored_params = self.recursive_queries(params)

            result_params = []
            if type(cur_prams) == list:
                for rp in refactored_params:
                    for cp in cur_prams:
                        prepared_list = copy(rp)
                        prepared_list.append(cp)
                        result_params.append(prepared_list)
                    pass

                return result_params
            else:
                rp: List
                for rp in refactored_params:
                    prepared_list = copy(rp)
                    prepared_list.append(cur_prams)
                    result_params.append(prepared_list)
                    pass
                return result_params

            pass
        else:
            if type(params[0]) == list:
                params = params.pop()
                pass
            return [params]
        pass

    def __prepare_params(self) -> dict:
        params_dict: dict = {}

        if self.__id_param is not None:
            params_dict['cve_id'] = f'cveId={self.__id_param}'
            pass

        if self.__severity_param is not None:
            severity_list = []
            for severity in self.__severity_param:
                severity_list = f'{self.__severity_cvss_param_name}={severity}'
                pass

            params_dict['severity'] = severity_list
            pass

        if self.__vector_param is not None or \
                self.__complexities_param is not None:

            vectors = []
            complexities = []

            if self.__vector_param is not None:
                for v in self.__vector_param:
                    vectors.append(f'AV:{v}')
                    pass
                pass

            if self.__complexities_param is not None:
                for c in self.__complexities_param:
                    complexities.append(f'AC:{c}')
                    pass
                pass

            result_metrics_params = []

            if len(vectors) == 0:
                for c in complexities:
                    result_metrics_params.append(f'{self.__metrics_cvss_param_name}={c}')
                pass
            elif len(complexities) == 0:
                for v in vectors:
                    result_metrics_params.append(f'{self.__metrics_cvss_param_name}={v}')
                pass
            else:
                for v in vectors:
                    for c in complexities:
                        result_metrics_params.append(f'{self.__metrics_cvss_param_name}={v}/{c}')
                        pass  # --for complex
                    pass  # --for vectors
                pass  # --else

            params_dict['metrics'] = result_metrics_params
            pass

        if self.__epss_param is not None:
            # params_dict[] = result_metrics_params
            pass

        if self.__date_param is not None:
            start_date = self.__date_param[0]
            end_date = self.__date_param[1]

            if start_date is None:
                start_date = datetime(1999, 9, 1)
                pass
            if end_date is None:
                end_date = datetime.now()
                pass
            start_date = start_date.replace(tzinfo=self.__timezone)
            end_date = end_date.replace(tzinfo=self.__timezone)

            days_diff = (end_date - start_date).days

            dates_params_list = []

            # params_dict['pubStartDate'] = []
            # params_dict['pubEndDate'] = []

            for day_num in range(0, days_diff, 120):
                cur_start_date = start_date + timedelta(days=day_num)
                cur_end_date = cur_start_date + + timedelta(days=120)

                cur_start_date_str = cur_start_date.isoformat()
                cur_end_date_str = cur_end_date.isoformat()

                param_str = f'pubStartDate={cur_start_date_str}&pubEndDate={cur_end_date_str}'
                param_str = param_str.replace('+', '%2B')
                dates_params_list.append(param_str)

                pass

            params_dict['date'] = dates_params_list
            pass

        key_words = []

        if self.__product_param is not None:
            key_words.extend(self.__product_param)
            pass

        if self._vendor_param is not None:
            key_words.extend(self._vendor_param)
            pass

        if len(key_words) != 0:
            keys = '%20'.join(key_words)
            params_dict['key_word'] = f'keywordSearch={keys}'
            pass

        if self.__mentions_param is not None:
            pass

        return params_dict
        pass

    def set_id_param(self, cve_id: str):
        self.__id_param = cve_id
        pass

    def set_severity_param(self, level: List[str]):
        severity_param = [l.upper() for l in level]
        for s in severity_param:
            assert s in self.__severity, "unknown severity level"
            pass
        # FIXME: понять пончему он не видит данные от наследуемого класса

        self.__severity_param = tuple(severity_param)
        pass

    def set_vector_param(self, vector: List[str]):
        # vector_param = [v.lower() for v in vector]
        vector_param = [NistApi.VECTORS_ABBR[v] for v in vector]
        self.__vector_param = tuple(vector_param)
        pass

    def set_complexity_param(self, complexity: List[str]):
        # complexity_param = [v.lower() for v in complexity]
        complexity_param = [NistApi.COMPLEXITY_ABBR[v] for v in complexity]
        self.__complexities_param = tuple(complexity_param)
        pass

    def set_epss_param(self, epss: Tuple[float, float]):
        self.__epss_param = tuple(epss)
        pass

    def set_date_param(self, date: Tuple[str, str]):
        # TODO: тут может быть ваш парсер

        start_date_str = date[0]
        end_date_str = date[1]

        if start_date_str is None:
            end_date = isoparser.isoparse(end_date_str)
            start_date = end_date - timedelta(days=120)
            pass
        elif end_date_str is None:
            start_date = isoparser.isoparse(start_date_str)
            end_date = start_date + timedelta(days=120)
        else:
            start_date = isoparser.isoparse(start_date_str)
            end_date = isoparser.isoparse(end_date_str)
            if end_date - start_date > timedelta(days=120):
                start_date = end_date - timedelta(days=120)
                pass
            pass

        self.__date_param = (start_date, end_date)
        pass

    def set_product_param(self, product: str):
        self.__product_param = [product]
        pass

    def set_vendor_param(self, vendor: str):
        self._vendor_param = [vendor]
        pass

    def set_mentions_param(self, mentions: Tuple[float, float]):
        self.__mentions_param = [mentions]
        pass

    @staticmethod
    def factory_method(ver) -> 'NistApi':
        match ver:
            case CvssVerEnum.VER2.value:
                return NistApi('cvssV2Severity',
                               'cvssV2Metrics',
                               CvssSeverityV2Enum.get_values())
            case CvssVerEnum.VER3.value:
                return NistApi('cvssV3Severity',
                               'cvssV3Metrics',
                               CvssSeverityV3Enum.get_values())
            case _:
                return NistApi('cvssV3Severity',
                               'cvssV3Metrics',
                               CvssSeverityV3Enum.get_values())

    pass
