from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext

from forms import FindCVEGroup

import logging as log

from keyboards.params_searching_cve_menu import find_cve_markup


router = Router()


@router.callback_query(F.data == "complexity_low")
async def process_callback_complexity_low(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to LOW
    """

    await state.update_data(complexity="LOW")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "complexity_medium")
async def process_callback_vector_complexity_medium(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to MEDIUM
    """

    await state.update_data(complexity="MEDIUM")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "complexity_high")
async def process_callback_complexity_high(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to HIGH
    """

    await state.update_data(complexity="HIGH")
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


