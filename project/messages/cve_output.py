from api.builders.cve_builder import Cve
from api.builders.trends_cve_builder import CveTrendsTuple

NONE_TEMPLATE = 'Нет информации  😞'


def get_cve_by_id_output_text(result_cve: Cve) -> str:
    additional_sources = ""
    products_with_version = ""
    pocs = ""
    print(result_cve.mentions.split())

    if result_cve.mentions is not None:
        for link in result_cve.mentions.split():
            additional_sources += f"""\n  -  <a href='{link}'>Дополнительный источник</a>"""
            
    else:
        additional_sources = NONE_TEMPLATE 

    if result_cve.poc is not None:
        for link in result_cve.poc:
            pocs += f"""\n  -  <a href='{link}'>poc</a>"""

    if result_cve.versions is not None and \
            result_cve.product is not None:

        versions = result_cve.versions.split()
        products = result_cve.product.split()

        for v, p in zip(versions, products):
            products_with_version += f"""\n  -  {p}: {v}"""
            pass
        pass
    else:
        products_with_version = NONE_TEMPLATE
        pass

    cve_link = get_param_or_template(result_cve.link)
    cve_id = get_param_or_template(result_cve.id)
    cve_date = get_param_or_template(result_cve.date)
    cve_cvss2 = get_param_or_template(result_cve.cvss2)
    cve_cvss3 = get_param_or_template(result_cve.cvss3)
    cve_score = get_param_or_template(result_cve.score)
    cve_vector = get_param_or_template(result_cve.vector)
    cve_complexity = get_param_or_template(result_cve.complexity)
    cve_epss = get_param_or_template(result_cve.epss)
    cve_products_with_version = get_param_or_template(products_with_version)
    cve_additional_sources = get_param_or_template(additional_sources)
    cve_mentions = get_param_or_template(result_cve.mentions)
    cve_description = get_param_or_template(result_cve.description)
    cve_elimination = get_param_or_template(result_cve.elimination, 'вовремя обновиться')
    cve_poc = get_param_or_template(pocs) # FIXME может быть пустой список!!!

    message = f"""
<b>По данному cve id найдена информация</b>:

① <b>Номер CVE</b>: <a href='{cve_link}'>{cve_id}</a>
② <b>Дата/время регистрации CVE</b>: {cve_date}
③ <b>CVSSv2</b>: {cve_cvss2}
④ <b>CVSSv3</b>: {cve_cvss3}
⑤ <b>Уровень критичности</b>: {cve_score}
⑥ <b>Вектор атаки</b>: {cve_vector}
⑦ <b>Сложность атаки</b>: {cve_complexity}
⑧ <b>EPSS рейтинг</b>: {cve_epss}
⑨ <b>Продукт/вендор и версия для которого характерна CVE</b>: {cve_products_with_version}
⑩ <b>Ссылки на статьи с упоминаниями и другая полезная информация</b>: {additional_sources}
⑪ <b>Описание CVE</b>: {cve_description}
⑫ <b>Необходимые действия по устранению уязвимости</b>: {cve_elimination}
⑬ <b>POC</b>: {cve_poc}

    """

    return message


def get_param_or_template(param, template=NONE_TEMPLATE):
    return param if param is not None else template


def get_trends_cve_output_text(result_cve: CveTrendsTuple, number: int) -> str:
    additional_sources = ""

    for item in result_cve.vendor_advisories:
        additional_sources += f"""\n  -  <a href='{item}'>Дополнительный источник</a>"""

    message = f"""
    Номер: {number + 1}
    
① <b>Номер CVE</b>: {result_cve.id}
  - <a href='https://www.cve.org/CVERecord?id={result_cve.id}'>read more on cve.org</a>
  - <a href='https://nvd.nist.gov/vuln/detail/{result_cve.id}'>read more on nvd.nist.gov</a>
  - <a href='https://cve.report/{result_cve.id}'>read more on cve.report</a> 
② <b>Дата/время регистрации CVE</b>: {result_cve.published_date}
③ <b>Количество просмотров</b>: {result_cve.audience_size}
④ <b>Статистика по социальным сетям</b>:
  -  <b>Количество упоминаний</b>: {result_cve.num_tweets_and_retweets}
  -  <b>Количество твитов</b>: {result_cve.num_tweets}
  -  <b>Количество ретвитов</b>: {result_cve.num_retweets}
  -  <b>Количество постов на редите</b>: {result_cve.nums_reddit_posts}
⑤ <b>CVSS v2</b>: {result_cve.cvss_v2_base_severity} ({result_cve.cvss_v2_base_score})
⑥ <b>CVSS v3</b>: {result_cve.cvss_v3_base_severity} ({result_cve.cvss_v3_base_score})
⑦ <b>Ссылки с полезной информацией</b>: {additional_sources}
⑧ <b>EPSS рейтинг</b> {result_cve.epss_score}
⑨ <b>Описание CVE:</b> {result_cve.description}

    """
    return message

def get_params_text(params: dict) -> str:

    result_text = ""
    
    for k, v in params.items():
        if not v: 
            params[k] = "Значение не задано"

    result_text = f"""
    <b>Вендор</b>: {params["vendor"]}
    <b>Продукт</b>: {params["product"]}
    <b>Начальная дата</b>: {params["start_date"]}
    <b>Конечная дата</b>: {params["end_date"]}
    <b>Версия CVSS</b>: {params["cvss_version"]}
    <b>Значение cvss</b>: {params["cvss_param"][0] if type(params["cvss_param"])==list else params["cvss_param"]}
    <b>Вектор</b>: {params["vector"][0] if type(params["vector"])==list else params["vector"]}
    <b>Сложность</b>: {params["complexity"][0] if type(params["complexity"])==list else params["complexity"]}
    """
    return result_text
