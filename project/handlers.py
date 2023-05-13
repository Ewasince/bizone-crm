from aiogram.filters import Command
from aiogram.types import Message
from aiogram import Bot, Dispatcher, Router, types

from config import config


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