from github import Github

api_token = "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"

g = Github(api_token)

repos = g.search_repositories("CVE-2017-0144")

for rep  in repos: 
    print(rep)



