import os

from pydantic import BaseModel
from dotenv import load_dotenv, find_dotenv

load_dotenv("secrets.env")
load_dotenv("config.env")

class Config(BaseModel):
    '''
    Основной класс конфига, выполняющий проверку всех полей
    '''

    # secrets
    bot_token: str

    # public config
    bot_name: str

    log_level: str
    log_file: str

    # делаем конфиг неизменяемым
    class Config:
        frozen = True

    pass


# создание конфига
config_dict = {}

for param in Config.__fields__:
    param: str
    config_dict[param] = os.environ.get(param.upper())
    pass

config = Config(**config_dict)
