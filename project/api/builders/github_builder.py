from typing import List

from api.builders.cve_builder import Cve
from api.github_api.github_api import GithubRepo
from config import config


class GithubBuilder:

    def __init__(self, github_repo: GithubRepo):
        self.__github_repo = github_repo
        pass

    def add_repos(self, cves: List[Cve]):
        for cve in cves:
            repos_links = self.__github_repo.get_poc_from_github(cve.id)
            cve.poc = repos_links
            pass

        return cves

    pass
