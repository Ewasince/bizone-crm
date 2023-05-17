import os

from pydantic import BaseModel

# __all__ = ['config']


class Config(BaseModel):
    """
    Основной класс конфига, выполняющий проверку всех полей
    """

    # secrets
    bot_token: str
    translator_token: str
    translator_folder: str
    github_token: str

    # public config
    bot_name: str

    log_level: str
    log_file: str

    cve_api: str
    cve_api_version: str

    max_cve_output: int

    add_translate: bool
    add_epss: bool
    add_poc: bool
    show_repos: int

    # делаем конфиг неизменяемым
    class Config:
        frozen = True

    pass


# создание конфига
__config_dict = {}

for param in Config.__fields__:
    param: str
    __config_dict[param] = os.environ.get(param.upper())
    pass

config = Config(**__config_dict)
