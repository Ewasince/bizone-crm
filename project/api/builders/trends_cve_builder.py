import logging as log
from collections import namedtuple
from typing import List, Optional

trend_tuple_fields = [
    "id",
    "cve_link",
    "audience_size",
    "num_tweets",
    "num_retweets",
    "num_tweets_and_retweets",
    "published_date",
    "cvss_v2_base_score",
    "cvss_v3_base_score",
    "cvss_v2_base_severity",
    "cvss_v3_base_severity",
    "description",
    "epss_score",
    "nums_reddit_posts",
    "graph_pict",
    "vendor_advisories", 
]
CveTrendsTuple = namedtuple('CveTrendsTuple', trend_tuple_fields)

class CveTrendsTupleBuilder:

    def __init__(self):
        self.__resul_cves: Optional[List[CveTrendsTuple]] = []
        self.__result_dict: dict
        self.reset()
        

    def reset(self):
        self.__result_dict = {k: None for k in trend_tuple_fields}
        self.__resul_cves = []
        

    def build(self, raw_data):
        
        for cve_data in raw_data:

            self.__result_dict["id"] = cve_data["cve"]
            self.__result_dict["cve_link"] = f"https://nvd.nist.gov/vuln/detail/{cve_data['cve'].upper()}"
            self.__result_dict["audience_size"] = cve_data["audience_size"]
            self.__result_dict["num_tweets"] = cve_data["num_tweets"]
            self.__result_dict["num_retweets"] = cve_data["num_retweets"]
            self.__result_dict["num_tweets_and_retweets"] = cve_data["num_tweets_and_retweets"]
            self.__result_dict["published_date"] = cve_data["publishedDate"]
            self.__result_dict["cvss_v2_base_score"] = cve_data["cvssv2_base_score"]
            self.__result_dict["cvss_v3_base_score"] = cve_data["cvssv3_base_score"]
            self.__result_dict["cvss_v2_base_severity"] = cve_data["cvssv2_severity"]
            self.__result_dict["cvss_v3_base_severity"] = cve_data["cvssv3_base_severity"]
            self.__result_dict["description"] = cve_data["description"]
            self.__result_dict["epss_score"] = cve_data["epss_score"]
            self.__result_dict["nums_reddit_posts"] = len(cve_data["reddit_posts"])
            self.__result_dict["vendor_advisories"] = cve_data["vendor_advisories"]

            self.__resul_cves.append(CveTrendsTuple(**self.__result_dict))


    def get_result(self) -> List[CveTrendsTuple]:
        return self.__resul_cves