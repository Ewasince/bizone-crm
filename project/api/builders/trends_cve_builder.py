# import seaborn as sb
# import matplotlib.pyplot as plt
# import numpy as np

from dataclasses import dataclass, fields
from typing import List, Optional


@dataclass
class CveTrendsTuple:
    id: str
    cve_link: str
    audience_size: str
    num_tweets: str
    num_retweets: str
    num_tweets_and_retweets: str
    published_date: str
    score_v2: str
    score_v3: str
    cvss_v2: str
    cvss_v3: str
    description: str
    epss_score: str
    nums_reddit_posts: str
    graph_pict: str
    vendor_advisories: str

    @staticmethod
    def get_fields():
        return [f.name for f in fields(CveTrendsTuple)]

    pass


class CveTrendsTupleBuilder:

    def __init__(self, period: str):
        self.__resul_cves: Optional[List[CveTrendsTuple]] = []
        self.__result_dict: dict
        self.__period = period
        self.reset()

    def reset(self):
        """
        Сбрасывает состояние билдера

        :return:
        """
        self.__result_dict = {k: None for k in CveTrendsTuple.get_fields()}
        self.__resul_cves = []

    def build(self, raw_data):
        """
        Создаёт объект СМУ из информации от trends_api

        :param raw_data:
        :return:
        """
        for cve_data in raw_data:
            self.__result_dict["id"] = cve_data["cve"]
            self.__result_dict["cve_link"] = f"https://nvd.nist.gov/vuln/detail/{cve_data['cve'].upper()}"
            self.__result_dict["audience_size"] = cve_data["audience_size"]
            self.__result_dict["num_tweets"] = cve_data["num_tweets"]
            self.__result_dict["num_retweets"] = cve_data["num_retweets"]
            self.__result_dict["num_tweets_and_retweets"] = cve_data["num_tweets_and_retweets"]
            self.__result_dict["published_date"] = cve_data["publishedDate"]
            self.__result_dict["score_v2"] = cve_data["cvssv2_base_score"]
            self.__result_dict["score_v3"] = cve_data["cvssv3_base_score"]
            self.__result_dict["cvss_v2"] = cve_data["cvssv2_severity"]
            self.__result_dict["cvss_v3"] = cve_data["cvssv3_base_severity"]
            self.__result_dict["description"] = cve_data["description"]
            self.__result_dict["epss_score"] = cve_data["epss_score"]
            self.__result_dict["nums_reddit_posts"] = len(cve_data["reddit_posts"])
            self.__result_dict["vendor_advisories"] = cve_data["vendor_advisories"]

            # self.__result_dict["graph_pict"] = self.generate_graph(cve_data["timegraph_data"])

            self.__resul_cves.append(CveTrendsTuple(**self.__result_dict))

    def get_result(self) -> List[CveTrendsTuple]:
        """
        Выдаёт результат

        :return:
        """
        return self.__resul_cves

    # def generate_graph(self, raw_data: List[Dict]):

    #     audience = [] # ()
    #     posts = [] # (tweets, retweets)

    #     for item in raw_data:
    #         audience.append(item["audience"])

    #         posts.append((item["tweets"], item["retweets"]))

    #     log.info(audience)
    #     log.info(posts)

    #     sb.set_style("whitegrid")
    #     x = np.linspace(1, 7, 7)
    #     for i in range(1, 5):
    #         plt.plot(x,  posts)
    #     plt.show()

# test
