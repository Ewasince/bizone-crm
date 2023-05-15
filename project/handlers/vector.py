from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext

from forms import FindCVEGroup

import logging as log

from keyboards.params_searching_cve_menu import find_cve_markup


router = Router()


@router.callback_query(F.data == "vector_local")
async def process_callback_vector_local(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to LOCAL
    """

    await state.update_data(vector="LOCAL")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "vector_adj_network")
async def process_callback_vector_adj_network(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to ADJACENT NETWORK
    """

    await state.update_data(vector="ADJACENT NETWORK")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "vector_network")
async def process_callback_vector_network(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to NETWORK
    """

    await state.update_data(vector="NETWORK")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )
