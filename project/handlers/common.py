from aiogram import Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import Message, CallbackQuery

from config import config
from forms import FindCVEGroup
from keyboards.main_menu import main_markup, greetings_markup
from keyboards.params_searching_cve_menu import find_cve_markup
from keyboards.valyable_cve_menu import most_valuable_cve_markup
from messages.cve_output import get_params_text

router = Router()


@router.message(Command(commands=["start"]))
async def command_start_handler(message: Message, state: FSMContext) -> None:
    """
        start command hadler
    """
    await message.answer(f"Привет, <b>{message.from_user.full_name}</b>! Меня зовут {config.bot_name}!" +
                         " Я помогу тебе получить актуальную информацию о сущетсвующих на данный момент CVE.",
                         reply_markup=greetings_markup)


@router.callback_query(F.data == "menu_btn")
async def process_callback_main_menu(callback_query: CallbackQuery, state: FSMContext):
    """
        main menu handler
    """
    await state.clear()
    await callback_query.message.answer("Главное меню", reply_markup=main_markup)


@router.callback_query(F.data == "find_cve_tg")
async def process_callback_find_cve(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu handler
    """

    """
        ТУТ СПИСОК ВСЕХ ПАРАМЕТРОВ 
        TODO ПОТОМ убрать коммент
    """
    await state.update_data(
        vendor=None,
        product=None,
        start_date=None,
        end_date=None,
        cvss_version=None,
        cvss_param=None,
        vector=None,
        complexity=None
    )
    user_data = await state.get_data()
    params_text = get_params_text(user_data)


    await callback_query.message.answer(f"Параметры запроса поиска: {params_text}", reply_markup=find_cve_markup)


@router.callback_query(F.data == "find_cve_by_id")
async def process_callback_add_id(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: handler for the button that adds the CVE`s id parameter
    """
    await callback_query.message.edit_text("Введите Id")
    await state.set_state(FindCVEGroup.id)


@router.callback_query(F.data == "valuable_cve")
async def process_callback_valuable_cve(callback_query: CallbackQuery, state: FSMContext):
    """
        valuable_cve menu handler
    """
    await callback_query.message.edit_text(
        "Выберите период, за который велась статистика популярности cve",
        reply_markup=most_valuable_cve_markup
    )
