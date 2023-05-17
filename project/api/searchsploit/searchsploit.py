import re
from typing import List, Tuple


def check_substring(line_list, blueprint):
    for word in line_list:
        if (re.findall(f'{blueprint}', word, flags=re.IGNORECASE)):
            return True
    return False


def split_file_lines():
    with open('project/api/searchsploit/all_modules.txt') as file:
        lines_list = file.readlines()
        for j in range(0, len(lines_list)):
            lines_list[j] += f' {j}'
        split_lines_list = []
        for i in range(0, len(lines_list)):
            split_lines_list.append(lines_list[i].split())
    return split_lines_list


def get_urls_list(input_request) -> List[Tuple[str, str]]:
    url_list = []
    print(len(cves_links))
    for line in cves_links:
        if check_substring(line, input_request):
            urls_base = ''
            if int(line[len(line) - 1]) < 1715:
                urls_base = 'https://www.rapid7.com/db/modules/'
            if (int(line[len(line) - 1]) < 2083) and (int(line[len(line) - 1]) > 1714):
                urls_base = 'https://www.rapid7.com/db/modules/auxiliary/'
            if (int(line[len(line) - 1]) < 3362) and (int(line[len(line) - 1]) > 2082):
                urls_base = 'https://www.rapid7.com/db/modules/payload/'
            if int(line[len(line) - 1]) > 3361:
                urls_base = 'https://www.rapid7.com/db/modules/encoder/'
                pass

            url_list.append((urls_base + line[1], line[1]))
            pass
        pass

    return url_list


cves_links = split_file_lines()

# print(get_urls_list(, 'voip'))
