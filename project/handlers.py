from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import Router, types, F

from config import config

import kb


router = Router()


@router.message(Command(commands=["start"]))
async def command_start_handler(message: Message) -> None:
    '''
    start command hadler
    '''
    await message.answer(f"Привет, <b>{message.from_user.full_name}</b>! Меня зовут {config.bot_name}!" +
                            " Я помогу тебе получить актуальную информацию о сущетсвующих на данный момент CVE.",
                            reply_markup=kb.greetings_markup)


@router.callback_query(F.data == "menu_btn")
async def process_callback_main_menu(callback_query: CallbackQuery):
    '''
        main menu handler
    '''
    await callback_query.message.answer("Главное меню епта (МОЖЕШЬ КНОПКИ НАЖАТЬ ЧУДИЩЕ):", reply_markup=kb.main_markup)


@router.callback_query(F.data == "")
async def process_callback(callback_query: CallbackQuery):
    pass


@router.message()
async def echo_handler(message: Message) -> None:
    '''
    other commands handler
    '''
    try:
        # Send copy of the received message
        await message.send_copy(chat_id=message.chat.id)
    except TypeError:
        # But not all the types is supported to be copied so need to handle it
        await message.answer("Nice try!")