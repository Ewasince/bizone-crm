import asyncio

from api.builders.cve_builder import Cve
from api.yandex_api.translator_api import TranslatorApi
from config import config
from typing import List


class TranslateBuilder:

    def __init__(self):
        self.__translator: TranslatorApi = TranslatorApi()
        pass

    async def a_bunch_translate(self, cve_list: List[Cve], only_first: bool = True):
        descriptions = [cve.description for cve in cve_list]

        texts_to_translate = descriptions

        if only_first and len(descriptions) > config.max_cve_output:
            texts_to_translate = descriptions[:5]
            pass

        translated_texts = await self.__translator.a_translate(texts_to_translate)

        descriptions[:5] = translated_texts

        for cve, desc in zip(cve_list, descriptions):
            cve.description = desc
            pass

        return cve_list

    pass


async def tests_func():
    descs = [
        '1 English texts for beginners to practice reading',
        '2 your comprehension of written English',
        '3 English texts for beginners to practice reading',
        '4 your comprehension of written English',
        '5 English texts for beginners to practice reading',
        '6 your comprehension of written English',
    ]

    translate_builder = TranslateBuilder()

    cve_tuples = []

    for text in descs:
        params = {k: None for k in Cve.get_fields()}
        params['description'] = text
        cve_tuples.append(Cve(**params))
        pass

    for c in cve_tuples:
        print(c)

    cve_tuples = await translate_builder.a_bunch_translate(cve_tuples)

    for c in cve_tuples:
        print(c)
    pass


if __name__ == '__main__':
    asyncio.run(tests_func())
