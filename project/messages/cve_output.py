import logging as log

from api.builders.cve_builder import Cve
from api.builders.trends_cve_builder import CveTrendsTuple
from api.nist_api.enums import VectorsEnum, ComplexityEnum, CvssSeverityV3Enum, CvssSeverityV2Enum

NONE_TEMPLATE = 'Нет информации  😞'

RU_NAMES_VECTOR = {VectorsEnum.LOCAL.value: "Локально",
                   VectorsEnum.ADJACENT_NETWORK.value: "Соседняя сеть",
                   VectorsEnum.NETWORK.value: "Сеть"}

RU_NAMES_COMPLEXITY = {ComplexityEnum.LOW.value: "Низкий",
                       ComplexityEnum.MEDIUM.value: "Средний",
                       ComplexityEnum.HIGH.value: "Высокий"}

RU_NAMES_CVSS3_LEVEL = {CvssSeverityV3Enum.LOW.value: "🔵 Низкий",
                        CvssSeverityV3Enum.MEDIUM.value: "🟡 Средний",
                        CvssSeverityV3Enum.HIGH.value: "🟠 Высокий",
                        CvssSeverityV3Enum.CRITICAL.value: "🔴 Критический"}

RU_NAMES_CVSS2_LEVEL = {CvssSeverityV2Enum.LOW.value: "🔵 Низкий",
                        CvssSeverityV2Enum.MEDIUM.value: "🟡 Средний",
                        CvssSeverityV2Enum.HIGH.value: "🔴 Высокий"}


class ParamsFormatter:

    # def __init__(self, cve: Cve):
    #     self.__cve = cve
    #     pass

    def get_id(self, id_):
        return self.__get_param_or_template(id_)

    def get_link(self, link):
        return self.__get_param_or_template(link)

    def get_date(self, date):
        return self.__get_param_or_template(date)

    def get_cvss2(self, cvss2):

        if cvss2 is None:
            return NONE_TEMPLATE

        try:
            cvss2 = RU_NAMES_CVSS2_LEVEL[cvss2]
        except Exception as e:
            log.warning(f'[ParamsFormatter] [get_complexity] vector correspondence error: {cvss2}, e={e}')
            pass

        return cvss2

    def get_cvss2_and_score(self, cvss2, score):

        if cvss2 is None and score is None:
            return NONE_TEMPLATE

        cvss2 = self.get_cvss2(cvss2)

        return f'{cvss2} ({score})'

    def get_cvss3(self, cvss3):

        if cvss3 is None:
            return NONE_TEMPLATE

        try:
            cvss3 = RU_NAMES_CVSS3_LEVEL[cvss3]
        except Exception as e:
            log.warning(f'[ParamsFormatter] [get_complexity] vector correspondence error: {cvss3}, e={e}')
            pass

        return cvss3

    def get_cvss3_and_score(self, cvss3, score):

        if cvss3 is None and score is None:
            return NONE_TEMPLATE

        cvss3 = self.get_cvss3(cvss3)

        return f'{cvss3} ({score})'

    # def get_score(self, score):
    #     return self.__get_param_or_template(score)

    def get_vector(self, vector):

        if vector is None:
            return NONE_TEMPLATE

        try:
            vector = RU_NAMES_VECTOR[vector]
        except Exception as e:
            log.warning(f'[ParamsFormatter] [get_vector] vector correspondence error: {vector}, e={e}')
            pass

        return vector

    def get_complexity(self, complexity):

        if complexity is None:
            return NONE_TEMPLATE

        try:
            complexity = RU_NAMES_COMPLEXITY[complexity]
        except Exception as e:
            log.warning(f'[ParamsFormatter] [get_complexity] vector correspondence error: {complexity}, e={e}')
            pass

        return complexity

    def get_epss(self, epss):
        return self.__get_param_or_template(epss)

    def get_products_with_version(self, product, versions):
        products_with_version = ""

        if versions is not None and \
                product is not None:

            versions = versions.split('\n')
            products = product.split('\n')

            for v, p in zip(versions, products):
                products_with_version += f"""\n  -  {p}: {v}"""
                pass
            pass
        else:
            products_with_version = NONE_TEMPLATE
            pass

        return products_with_version

    def get_mentions(self, mentions):
        additional_sources = ""

        if mentions is not None:
            for link in mentions:
                additional_sources += f"""\n  -  <a href='{link}'>Дополнительный источник</a>"""
                pass
            pass
        else:
            additional_sources = NONE_TEMPLATE

        return additional_sources

    def get_description(self, description):
        return self.__get_param_or_template(description)

    def get_pocs(self, pocs):
        pocs_str = ""

        if pocs is not None and len(pocs) > 0:
            for link in pocs:
                pocs_str += f"""\n  -  <a href='{link}'>poc</a>"""
                pass
            pass
        else:
            return NONE_TEMPLATE

        return pocs_str

    def get_eliminations(self, elimination):
        return self.__get_param_or_template(elimination, 'Скачать обновление с сайта производителя')

    def __get_param_or_template(self, param, template=NONE_TEMPLATE):
        return param if param is not None else template

    # def get_audience(self, audience):
    #     pass
    #
    # def get_tweets_retweets(self, tweets_retweets):
    #     pass
    #
    # def get_tweets(self, tweets):
    #     pass
    #
    # def get_retweets(self, retweets):
    #     pass
    #
    # def get_reddit(self, reddit):
    #     pass
    pass


def get_cve_by_id_output_text(cve: Cve) -> str:
    formatter = ParamsFormatter()

    message = f"""
<b>По данному cve id найдена информация</b>:

① <b>Номер CVE</b>: <a href='{formatter.get_link(cve.id)}'>{formatter.get_id(cve.id)}</a>
② <b>Дата/время регистрации CVE</b>: {formatter.get_date(cve.date)}
⑤ <b>Уровень критичности CVSS v2</b>: {formatter.get_cvss2_and_score(cve.cvss2, cve.score_v2)}
⑤ <b>Уровень критичности CVSS v3</b>: {formatter.get_cvss3_and_score(cve.cvss3, cve.score_v3)}
⑥ <b>Вектор атаки</b>: {formatter.get_vector(cve.vector)}
⑦ <b>Сложность атаки</b>: {formatter.get_complexity(cve.complexity)}
⑧ <b>EPSS рейтинг</b>: {formatter.get_epss(cve.epss)}
⑨ <b>Продукт/вендор и версия для которого характерна CVE</b>: {formatter.get_products_with_version(cve.product, cve.versions)}
⑩ <b>Ссылки на статьи с упоминаниями и другая полезная информация</b>: {formatter.get_mentions(cve.mentions)}
⑪ <b>Описание CVE</b>: {formatter.get_description(cve.description)}
⑫ <b>Необходимые действия по устранению уязвимости</b>: {formatter.get_eliminations(cve.elimination)}
⑬ <b>POC</b>: {formatter.get_pocs(cve.poc)}
    """

    return message


def get_trends_cve_output_text(cve: CveTrendsTuple, number: int) -> str:
    formatter = ParamsFormatter()

    # additional_sources = ""
    #
    # for item in result_cve.vendor_advisories:
    #     additional_sources += f"""\n  -  <a href='{item}'>Дополнительный источник</a>"""

    message = f"""
    Номер: {number + 1}
    
① <b>Номер CVE</b>: {formatter.get_id(cve.id)}
  - <a href='https://www.cve.org/CVERecord?id={formatter.get_id(cve.id)}'>прочитать больше на on cve.org</a>
  - <a href='https://nvd.nist.gov/vuln/detail/{formatter.get_id(cve.id)}'>прочитать больше на nvd.nist.gov</a>
  - <a href='https://cve.report/{formatter.get_id(cve.id)}'>прочитать больше на cve.report</a> 
② <b>Дата/время регистрации CVE</b>: {formatter.get_date(cve.published_date)}
③ <b>Количество просмотров</b>: {cve.audience_size}
④ <b>Статистика по социальным сетям</b>:
  -  <b>Количество упоминаний</b>: {cve.num_tweets_and_retweets}
  -  <b>Количество твитов</b>: {cve.num_tweets}
  -  <b>Количество ретвитов</b>: {cve.num_retweets}
  -  <b>Количество постов на редите</b>: {cve.nums_reddit_posts}
⑤ <b>CVSS v2</b>: {formatter.get_cvss2_and_score(cve.cvss_v2, cve.score_v2)} 
⑥ <b>CVSS v3</b>: {formatter.get_cvss3_and_score(cve.cvss_v3, cve.score_v3)}
⑦ <b>Ссылки с полезной информацией</b>: {formatter.get_mentions(cve.vendor_advisories)}
⑧ <b>EPSS рейтинг</b> {formatter.get_epss(cve.epss_score)}
⑨ <b>Описание CVE:</b> {formatter.get_description(cve.description)}
    """
    return message


EMPTY_PARAM_TEMPLATE = 'Значение не задано'


def get_params_text(params: dict) -> str:
    for k, v in params.items():
        if not v:
            params[k] = None
            pass
        pass

    formatter = ParamsFormatter()

    if params["cvss_version"] is not None:
        match params["cvss_version"]:
            case '2':
                cvss_func = formatter.get_cvss2
            case '3':
                cvss_func = formatter.get_cvss3
            case _:
                cvss_func = formatter.get_cvss3

        levels = []
        for level in params["cvss_param"]:
            levels.append(cvss_func(level))
            pass
        params["cvss_param"] = ', '.join(levels)
        pass

    if params["vector"] is not None:
        vectors = []
        for vector in params["vector"]:
            vectors.append(formatter.get_vector(vector))
            pass
        params["vector"] = ', '.join(vectors)
        pass

    if params["complexity"] is not None:
        complexities = []
        for complexity in params["complexity"]:
            complexities.append(formatter.get_complexity(complexity))
            pass
        params["complexity"] = ', '.join(complexities)
        pass

    result_text = f"""
    <b>Вендор</b>: {params["vendor"] if params["vendor"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Продукт</b>: {params["product"] if params["product"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Начальная дата</b>: {params["start_date"] if params["start_date"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Конечная дата</b>: {params["end_date"] if params["end_date"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Версия CVSS</b>: {params["cvss_version"] if params["cvss_version"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Значение cvss</b>: {params["cvss_param"] if params["cvss_param"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Вектор</b>: {params["vector"] if params["vector"] is not None else EMPTY_PARAM_TEMPLATE}
    <b>Сложность</b>: {params["complexity"] if params["complexity"] is not None else EMPTY_PARAM_TEMPLATE}
    """
    return result_text
