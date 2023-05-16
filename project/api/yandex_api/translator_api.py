import asyncio
import json
from typing import List
import logging as log

from aiogram.client.session import aiohttp

from config import config

IAM_TOKEN = config.translator_token
folder_id = config.translator_folder


class TranslatorApi:
    __target_language = 'ru'
    __source_language = 'en'
    __url = 'https://translate.api.cloud.yandex.net/translate/v2/translate'

    async def atranslate(self, texts: List[str]) -> List[str]:
        body = {
            "targetLanguageCode": TranslatorApi.__target_language,
            "sourceLanguageCode": TranslatorApi.__source_language,
            "texts": texts,
            "folderId": folder_id,
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(IAM_TOKEN)
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(TranslatorApi.__url,
                                    json=body,
                                    headers=headers) as resp:  # открытие сессии в aiohttp

                if resp.status != 200:
                    log.warning(
                        f"[aexecute_request] cannot get json={body}, headers={headers}, status_code={resp.status}")
                    raise Exception('Response error')

                response_text = await resp.text()

                pass  # --with post
            pass  # --with session

        translated_text_raw = json.loads(response_text)
        result_texts = []

        for translation in translated_text_raw['translations']:
            result_texts.append(translation['text'])
            pass

        return result_texts

        pass

    pass


if __name__ == '__main__':
    translator = TranslatorApi()

    asyncio.run(translator.atranslate(['hellow, world!']))
