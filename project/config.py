import os

from pydantic import BaseModel

# from dotenv import load_dotenv, find_dotenv

# load_dotenv("secrets.env")
# load_dotenv("config.env")

# __all__ = ['config']


class Config(BaseModel):
    """
    Основной класс конфига, выполняющий проверку всех полей
    """

    # secrets
    bot_token: str

    # public config
    bot_name: str

    log_level: str
    log_file: str

    cve_api: str
    cve_api_version: str

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
