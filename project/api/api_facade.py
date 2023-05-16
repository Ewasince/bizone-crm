from api.builders.epss_builder import EpssBuilder
from api.builders.translate_builder import TranslateBuilder
from api.cve_repository import CveRepository
from api.epss_api.epss_api import EpssApi
from api.nist_api.nist_api import NistApi
from api.trends_api.trends_api import TrendsApi
from api.yandex_api.translator_api import TranslatorApi


def get_cve_repo(ver_cvss):
    """
    Метод-фасад, который скрывает создание классов апи для создания класса репозитория

    :param ver_cvss: Версия CVSS. Пример: '2', '31', None
    :return:
    """

    translator_api = TranslatorApi()
    translate_builder = TranslateBuilder(translator_api)

    nist_api = NistApi.factory_method(ver_cvss)
    trends_api = TrendsApi()

    epss_api = EpssApi()
    epss_builder = EpssBuilder(epss_api)

    cve_repo = CveRepository(nist_api, translate_builder, trends_api, epss_builder)

    return cve_repo

# async def test_a_get_cve_by_id():
#     test_cve_id = 'CVE-2019-1010218'
#
#     # test_cve_id = 'CVE-2017-0144'
#     # test_cve_id = 'CVE-2022-42889'
#
#     res = await a_get_cve_by_id(test_cve_id)
#
#     print(res)
#
#
# async def test_a_get_cve_by_params():
#     res = await a_get_cve_by_params(cvss_ver='2',
#                                    cvss=['LOW'],
#                                    qm=None,
#                                    vector=['NETWORK'],
#                                    complexity=None,
#                                    epss=None,
#                                    date=None,
#                                    product=None,
#                                    vendor=None,
#                                    mentions=None,
#                                    )
#
#     print(res)
#     pass
#
#
# async def test_a_get_trends_cve():
#     res = await a_get_trends_cve()
#     print(res)
#
#
# if __name__ == '__main__':
#     # test_func = test_a_get_cve_by_id
#     test_func = test_a_get_cve_by_params
#
#     asyncio.run(test_func())
