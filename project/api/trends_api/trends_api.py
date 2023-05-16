from typing import List
from api.builders.trends_cve_builder import CveTrendsTuple, CveTrendsTupleBuilder

import aiohttp
import asyncio
import logging as log


class TrendsApi:
    def __init__(self) -> None:
        self.url : str
        self.period : str

    async def aexecute_request(self):

        cve_row_list = []

        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as resp:

                if resp.status != 200: 
                    log.warning( f"[aexecute_request] cannot get url={self.url}, status_code={resp.status}")
                    raise Exception('Response error')

                resp_row_data = await resp.json()

                cve_row_list = resp_row_data["data"]
        
        builder = CveTrendsTupleBuilder(self.period)
        builder.build(cve_row_list)

        result_tuples = builder.get_result()

        return result_tuples
    
    def set_url(self, period: str):
        self.url = f"https://cvetrends.com/api/cves/{period}"
        self.period = period

    

