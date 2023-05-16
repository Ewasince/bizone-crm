from github import Github
from typing import List
from config import config


def get_poc_from_github(cve_id: str) -> List[str]:
    g = Github(config.github_token)

    result_repos = g.search_repositories(cve_id)

    for rep  in result_repos: 
        print(rep.html_url)


# if __name__ == "__main__":
#     print(get_poc_from_github("CVE-2017-0144"))

