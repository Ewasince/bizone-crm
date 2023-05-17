from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.nist_api.enums import ComplexityEnum
from keyboards.params_searching_cve_menu import find_cve_markup
from messages.cve_output import get_params_text

router = Router()


@router.callback_query(F.data == "complexity_low")
async def process_callback_complexity_low(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to LOW
    """

    await state.update_data(complexity=[ComplexityEnum.LOW.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Сложность успешно установлена. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "complexity_medium")
async def process_callback_vector_complexity_medium(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to MEDIUM
    """

    await state.update_data(complexity=[ComplexityEnum.MEDIUM.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Сложность успешно установлена. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "complexity_high")
async def process_callback_complexity_high(callback_query: CallbackQuery, state: FSMContext):
    """
        complexity_menu: Handler for the button that sets vector parameter to HIGH
    """

    await state.update_data(complexity=[ComplexityEnum.HIGH.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Сложность успешно установлена. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )


