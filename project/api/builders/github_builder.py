from typing import List
import logging as log

from api.builders.cve_builder import Cve
from api.github_api.github_api import GithubRepo
from config import config


class GithubBuilder:

    def __init__(self, github_repo: GithubRepo):
        self.__github_repo = github_repo
        pass

    def add_repos(self, cves: List[Cve]):
        """
        Получает и добавляет репозитории с возможными POC'ами в существующий список СМУ

        :param cves:
        :return:
        """
        try:
            for cve in cves:
                repos_links = self.__github_repo.get_poc_from_github(cve.id)
                cve.poc = repos_links
                pass
        except Exception as e:
            log.warning(f'[GithubBuilder] [add_repos] error find repos, e={e}')
            pass

        return cves

    pass
