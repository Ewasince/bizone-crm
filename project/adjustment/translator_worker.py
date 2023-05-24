import asyncio
import json

import aiohttp
import logging as log

from adjustment.config import config


class TranslatorTokenWorker:
    __token_url = 'https://iam.api.cloud.yandex.net/iam/v1/tokens'

    def __init__(self, oauth_token: str):
        self.__token_data = f"{{\"yandexPassportOauthToken\":\"{oauth_token}\"}}"
        pass

    async def get_ima_token(self):
        async with aiohttp.ClientSession() as session:
            async with session.post(self.__token_url, data=self.__token_data) as resp:  # открытие сессии в aiohttp
                log.debug(
                    f"[TranslatorTokenWorker] [get_ima_token] url request, url={self.__token_url}, data={self.__token_data}")
                if resp.status != 200:
                    log.warning(
                        f"[get_ima_token] cannot get url={self.__token_url}, status_code={resp.status}")
                    raise Exception('Response error')

                token_data_raw = await resp.text()
                pass  # -- post
            pass  # -- session
        token_data = json.loads(token_data_raw)

        token = token_data['iamToken']

        return token

        pass  # -- def

    pass


async def ima_token_worker():
    w = TranslatorTokenWorker(config.translator_oauth)

    while True:
        token = w.get_ima_token()
        config.set_translator_token(token)
        await asyncio.sleep(3600)
        pass


if __name__ == '__main__':
    w = TranslatorTokenWorker(config.translator_oauth)

    asyncio.run(w.get_ima_token())
    pass
