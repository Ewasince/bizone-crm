from aiogram import Router, F

from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.nist_api.enums import VectorsEnum
from keyboards.params_searching_cve_menu import find_cve_markup
from messages.cve_output import get_params_text

router = Router()


@router.callback_query(F.data == "vector_local")
async def process_callback_vector_local(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to LOCAL
    """

    await state.update_data(vector=[VectorsEnum.LOCAL.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Вектор успешно установлен. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "vector_adj_network")
async def process_callback_vector_adj_network(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to ADJACENT NETWORK
    """

    await state.update_data(vector=[VectorsEnum.ADJACENT_NETWORK.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Вектор успешно установлен. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "vector_network")
async def process_callback_vector_network(callback_query: CallbackQuery, state: FSMContext):
    """
        vector_menu: Handler for the button that sets vector parameter to NETWORK
    """

    await state.update_data(vector=[VectorsEnum.NETWORK.value])
    user_data = await state.get_data()
    params = get_params_text(user_data)

    await callback_query.message.edit_text(
        f"Вектор успешно установлен. Установленные параметры:: {params}",
        reply_markup=find_cve_markup
    )
