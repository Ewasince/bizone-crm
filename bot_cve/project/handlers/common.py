from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from forms import FindCVEGroup


from config import config

import kb

router = Router()


@router.message(Command(commands=["start"]))
async def command_start_handler(message: Message, state: FSMContext) -> None:
    '''
        start command hadler
    '''
    await message.answer(f"Привет, <b>{message.from_user.full_name}</b>! Меня зовут {config.bot_name}!" +
                            " Я помогу тебе получить актуальную информацию о сущетсвующих на данный момент CVE.",
                            reply_markup=kb.greetings_markup)
    


@router.callback_query(F.data == "menu_btn")
async def process_callback_main_menu(callback_query: CallbackQuery, state: FSMContext):
    '''
        main menu handler
    '''
    await state.clear()
    await callback_query.message.answer("Главное меню", reply_markup=kb.main_markup)



