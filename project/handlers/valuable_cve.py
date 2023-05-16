from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from api.cve_api import aget_trends_cve

from forms import FindCVEGroup

from config import config

import logging as log

from keyboards.main_menu import main_markup


router = Router()


@router.callback_query(F.data == "most_valuable_day")
async def procress_callback_most_valuable_day(callback_query: CallbackQuery, state: FSMContext):
    """
        valuable_cve: Handler for button that sets the parameter period to day 
    """
    period = "24hrs"
    result = []
    
    try: 
        result = await aget_trends_cve(period)

    except Exception as e:
        log.warning(f"[valuable_cve] {e}")

    for i in range(len(result)): 

        await callback_query.message.answer(
            text=f"Номер №{i+1}: {result[i]}"
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

    try: 
        result = await aget_trends_cve(period)

    except Exception as e:
        log.warning(f"[valuable_cve] {e}")

    for i in range(len(result)): 

        await callback_query.message.answer(
            text=f"Номер №{i+1}: {result[i]}"
        )

    await callback_query.message.answer(
        text="Меню",
        reply_markup=main_markup
    )