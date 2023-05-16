import logging as log

from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.api_facade import get_cve_repo
from keyboards.main_menu import main_markup
from messages.cve_output import get_trends_cve_output_text

router = Router()


@router.callback_query(F.data == "most_valuable_day")
async def procress_callback_most_valuable_day(callback_query: CallbackQuery, state: FSMContext):
    """
        valuable_cve: Handler for button that sets the parameter period to day 
    """
    period = "24hrs"
    result = []

    cve_repo = get_cve_repo(None)

    try:
        result = await cve_repo.a_get_trends_cve(period)

    except Exception as e:
        log.warning(f"[valuable_cve] {e}")

    for i in range(len(result)):
        await callback_query.message.answer(
            text=get_trends_cve_output_text(result[i], i)
        )

    await callback_query.message.answer(
        text="Меню",
        reply_markup=main_markup
    )


@router.callback_query(F.data == "most_valuable_week")
async def procress_callback_most_valuable_week(callback_query: CallbackQuery, state: FSMContext):
    """
        valuable_cve: Handler for button that sets the parameter period to week
    """
    period = "7days"
    result = []

    cve_repo = get_cve_repo(None)

    try:
        result = await cve_repo.a_get_trends_cve(period)

    except Exception as e:
        log.warning(f"[valuable_cve] {e}")

    for i in range(len(result)):
        await callback_query.message.answer(
            text=get_trends_cve_output_text(result[i], i)
        )

    await callback_query.message.answer(
        text="Меню",
        reply_markup=main_markup
    )
