import asyncio
from typing import Optional, List, Tuple
from datetime import datetime

from api.nist_api.nist_api import NistApi
from api.builders.cve_builder import CveTuple
from api.builders.trends_cve_builder import CveTrendsTuple
from api.nist_api.nist_api_factory import NistApiFactory
from api.trends_api.trends_api import TrendsApi


async def aget_cve_by_id(cve_id: str) -> List[CveTuple]:
    """
    returns a list of CveTuple by passed cve id
    """

    nist_api = NistApi(None, None, None)

    nist_api.set_id_param(cve_id)
    cve = await nist_api.aexecute_request()

    return cve

    pass


async def aget_cve_by_params(cvss_ver: str,
                             cvss: Optional[List[str]],
                             qm: Optional[None],
                             vector: Optional[List[str]],
                             complexity: Optional[List[str]],
                             epss: Optional[Tuple[float, float]],
                             date: Optional[List[str]],
                             product: Optional[str],
                             vendor: Optional[str],
                             mentions: Optional[Tuple[float, float]]
                             ) -> List[CveTuple]:
    """
    Принимает на вход критерии поиска и выдаёт cve по этим критериям. Если вместо критерия передано None, критерий
    при поиске не учитывается


    :param self:
    :param cvss_ver: Версия CVSS. Пример: '2', '31'
    :param cvss: список из уровней опасности, пример: ['HIGH', 'LOW'] ['MEDIUM']
    :param qm: пока пустой параметр
    :param vector: список векторов атаки, пример: ['NETWORK', 'LOCAL'], ['ADJACENT NETWORK']
    :param complexity: сложность применения уязвимости, пример: ['HIGH', 'LOW'] ['MEDIUM']
    :param epss: вероятность применения хацкерами данной уязвимости. передается как кортеж из нижнего и верхнего
    диапазона. Если граница диапазона отсутствует, то передаётся None. Пример: (1.0, 5.0), (8.0, None)
    :param date: Дата публикации cve. Передаётся кортеж, содержащий верхний и нижний предел. Если граница отсутствует,
    передаётся None. Пример: (datetime(2022,01,01, None)
    :param product: Наименование продукта. Пример: windows_10
    :param vendor: Наименование издателя. Пример: microsoft
    :param mentions: Количество упоминаний. Если граница отсутствует, передаётся None. Пример: (228, 1337), (42, None)
    :return:
    """

    nist_api = NistApiFactory.get_instance(cvss_ver)

    if cvss is not None:
        nist_api.set_severity_param(cvss)
        pass

    if vector is not None:
        nist_api.set_vector_param(vector)
        pass

    if complexity is not None:
        nist_api.set_complexity_param(complexity)
        pass

    if epss is not None:
        nist_api.set_epss_param(epss)
        pass

    if date is not None:
        nist_api.set_date_param(date)
        pass

    if product is not None:
        nist_api.set_product_param(product)
        pass

    if vendor is not None:
        nist_api.set_vendor_param(vendor)
        pass    

    if mentions is not None:
        nist_api.set_mentions_param(mentions)
        pass

    result = await nist_api.aexecute_request()

    return result


async def aget_trends_cve(period: str):
    """
        Getting the most popular cve
    """

    api = TrendsApi()
    api.set_url(period)

    cve_list: List[CveTrendsTuple] = await api.aexecute_request()

    return cve_list


async def test_aget_cve_by_id():
    test_cve_id = 'CVE-2019-1010218'

    # test_cve_id = 'CVE-2017-0144'
    # test_cve_id = 'CVE-2022-42889'

    res = await aget_cve_by_id(test_cve_id)

    print(res)


async def test_aget_cve_by_params():
    res = await aget_cve_by_params(cvss_ver='2',
                                   cvss=['LOW'],
                                   qm=None,
                                   vector=['NETWORK'],
                                   complexity=None,
                                   epss=None,
                                   date=None,
                                   product=None,
                                   vendor=None,
                                   mentions=None,
                                   )

    print(res)
    pass


async def test_aget_trends_cve():
    res = await aget_trends_cve()
    print(res)


if __name__ == '__main__':
    # test_func = test_aget_cve_by_id
    test_func = test_aget_cve_by_params

    asyncio.run(test_func())
