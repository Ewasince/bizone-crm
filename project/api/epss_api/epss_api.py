import json
from typing import List
import logging as log

from aiogram.client.session import aiohttp


class EpssApi:
    __base_url = 'https://api.first.org/data/v1/epss?cve'
    __cve_per_request = 110

    async def a_get_epss_api(self, cve_ids: List[str]) -> List[str]:

        cve_num = EpssApi.__cve_per_request
        cve_epss_datas = []

        for i in range(0, len(cve_ids), cve_num):
            url = EpssApi.__base_url + '=' + ','.join(cve_ids[i:cve_num])
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    log.debug(
                        f"[EpssApi] [a_get_epss_api] url request, url={url}")
                    if resp.status != 200:
                        log.warning(
                            f"[EpssApi] [a_get_epss_api] cannot get url={url}, status_code={resp.status}")
                        raise Exception('Response error')
                    cve_epss_datas.append(await resp.text())
                    pass
                pass

        epss_list = []
        for data in cve_epss_datas:
            cve_info = json.loads(data)
            for cve in cve_info['data']:
                epss_list.append(cve['epss'])
                pass
            pass

        return epss_list

    pass
