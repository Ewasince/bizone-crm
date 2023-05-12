import os
import logging
from logging import handlers
import sys
import asyncio

from aiogram import Bot, Dispatcher, Router, types
from aiogram.filters import Command
from aiogram.types import Message

from config import config

log = logging.getLogger('')
log.setLevel(logging.DEBUG)
format = logging.Formatter(
    '%(filename)17s[LINE:%(lineno)3d]# %(levelname)-6s [%(asctime)s]  %(message)s')

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(format)
console_handler.setLevel(config.log_level)
log.addHandler(console_handler)

file_handler = handlers.TimedRotatingFileHandler(
    config.log_file,
    when='midnight',
    backupCount=14,
    encoding=None,
    delay=False,
    utc=True)
file_handler.setFormatter(format)
file_handler.setLevel('DEBUG')
log.addHandler(file_handler)

router = Router()


@router.message(Command(commands=["start"]))
async def command_start_handler(message: Message) -> None:
    '''
    start command hadler
    '''
    await message.answer(f"Hello, <b>{message.from_user.full_name}</b>! My name is {config.bot_name}!")


@router.message()
async def echo_handler(message: types.Message) -> None:
    '''
    other commands handler
    '''
    try:
        # Send copy of the received message
        await message.send_copy(chat_id=message.chat.id)
    except TypeError:
        # But not all the types is supported to be copied so need to handle it
        await message.answer("Nice try!")


async def main() -> None:
    dp = Dispatcher()
    dp.include_router(router)

    bot = Bot(config.bot_token, parse_mode="HTML")
    await dp.start_polling(bot)


if __name__ == "__main__":
    log.debug(f'bot starter with config: {config.__dict__}')

    asyncio.run(main())
