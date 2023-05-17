from github import Github
from typing import List
from config import config


class GithubRepo:

    def get_poc_from_github(self, cve_id: str) -> List[str]:
        """
        Получиение информации о репозиториях по CVE id

        :param cve_id:
        :return:
        """
        github_api = Github(config.github_token)

        repos = github_api.search_repositories(cve_id)

        sorted_repos = sorted(repos, key=lambda rep: rep.stargazers_count, reverse=True)
        result_repos = sorted_repos[:config.show_repos]
        result_urls = [rep.html_url for rep in result_repos]

        return result_urls


if __name__ == "__main__":
    g = GithubRepo()
    print(g.get_poc_from_github("CVE-2017-0144"))
    pass
