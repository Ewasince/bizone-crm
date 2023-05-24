import os

from pydantic import BaseModel, Field


# __all__ = ['config']


class Config(BaseModel):
    """
    Основной класс конфига, выполняющий проверку всех полей
    """

    # secrets
    bot_token: str = Field(allow_mutation=False)
    translator_oauth: str = Field(allow_mutation=False)
    translator_token: str | None = Field(default=None, allow_mutation=True)
    # translator_token: str | None
    translator_folder: str = Field(allow_mutation=False)
    github_token: str = Field(allow_mutation=False)

    # public config
    bot_name: str = Field(allow_mutation=False)

    log_level: str = Field(allow_mutation=False)
    log_file: str = Field(allow_mutation=False)

    cve_api: str = Field(allow_mutation=False)
    cve_api_version: str = Field(allow_mutation=False)

    max_cve_output: int = Field(allow_mutation=False)
    show_repos: int = Field(allow_mutation=False)
    show_searchsploit: int = Field(allow_mutation=False)

    add_translate: bool = Field(allow_mutation=False)
    add_epss: bool = Field(allow_mutation=False)
    add_poc: bool = Field(allow_mutation=False)

    # делаем конфиг неизменяемым
    class Config:
        # frozen = True
        validate_assignment = True
        pass

    def set_translator_token(self, token: str):
        self.translator_token = token
        pass

    pass


# создание конфига
__config_dict = {}

for param in Config.__fields__:
    param: str
    __config_dict[param] = os.environ.get(param.upper())
    pass

config = Config(**__config_dict)

if __name__ == '__main__':
    test = config.translator_oauth

    config.translator_oauth = 'aaa'
    # config.set_translator_token('aaa')
    test1 = config.translator_oauth
    pass
