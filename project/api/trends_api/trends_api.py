import logging as log

import aiohttp

from api.builders.trends_cve_builder import CveTrendsTupleBuilder


class TrendsApi:
    __base_url: str = 'https://cvetrends.com/api/cves/'

    def __init__(self) -> None:
        self.__url = ''
        self.__period: str = ''
        pass

    async def a_execute_request(self):
        cve_row_list = []

        if self.__url == '' or self.__period == '':
            raise Exception(f'Wasn\'t passer period period={self.__period}')

        async with aiohttp.ClientSession() as session:
            async with session.get(self.__url) as resp:
                log.debug(
                    f"[TrendsApi] [a_execute_request] url request, url={self.__url}")
                if resp.status != 200:
                    log.warning(
                        f"[TrendsApi] [a_execute_request] cannot get url={self.__url}, status_code={resp.status}")
                    raise Exception('Response error')

                resp_row_data = await resp.json()

                cve_row_list = resp_row_data["data"]
                pass
            pass

        builder = CveTrendsTupleBuilder(self.__period)
        builder.build(cve_row_list)

        result_tuples = builder.get_result()

        return result_tuples

    def set_url(self, period: str):
        self.__url = f"{TrendsApi.__base_url}{period}"
        self.__period = period
