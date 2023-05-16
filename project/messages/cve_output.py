from api.builders.cve_builder import Cve
from api.builders.trends_cve_builder import CveTrendsTuple


def get_cve_by_id_output_text(result_cve: Cve) -> str:
    additional_sources = ""
    products_vith_version = ""

    for link in result_cve.mentions.split():
        additional_sources += f"""
    <a href='{link}'>Дополнительный источник</a>"""
        
    versions = result_cve.versions.split()
    products = result_cve.product.split()
    
    for i in range(len(products)):
        products_vith_version += f"""
    {products[i]}.{versions[i]}"""

    message = f"""
<b>По данному cve id найдена информация</b>:

① <b>Номер CVE</b>: <a href='{result_cve.link}'>{result_cve.id}</a>
② <b>Дата/время регистрации CVE</b>: {result_cve.date}
③ <b>CVSSv2</b>: {result_cve.cvss2}
④ <b>CVSSv3</b>: {result_cve.cvss3}
⑤ <b>Уровень критичности</b>: {result_cve.score}
⑥ <b>Вектор атаки</b>: {result_cve.vector}
⑦ <b>Сложность атаки</b>: {result_cve.complexity}
⑧ <b>EPSS рейтинг</b>: {result_cve.epss}
⑨ <b>Продукт/вендор и версия для которого характерна CVE</b>: {products_vith_version}
⑩ <b>Ссылки на статьи с упоминаниями и другая полезная информация</b>: {additional_sources}
⑪ <b>Информация о количестве упоминаний</b>: {result_cve.mentions}
⑫ <b>Описание CVE</b>: {result_cve.description}
⑬ <b>Необходимые действия по устранению уязвимости</b>: {result_cve.elimination if result_cve.elimination else 'вовремя обновиться'}
⑭ <b>POC</b>: В разработке

    """

    return message


def get_trends_cve_output_text(result_cve: CveTrendsTuple, number: int) -> str:

    additional_sources = ""

    for item in result_cve.vendor_advisories:
        additional_sources += f"""
    <a href='{item}'>Дополнительный источник</a>"""
    

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