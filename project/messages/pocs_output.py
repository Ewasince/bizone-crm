from typing import List, Tuple


def get_pocs_links_text(links: List[Tuple[str, str]]) -> str:
    res_text = 'Смотри, что я нашёл:\n'

    res_links = [f'''<a href='{l}'>{p}</a>''' for l, p in links]

    res_text += '\n'.join(res_links)

    return res_text
