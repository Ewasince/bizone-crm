from aiogram import Router, F

from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.nist_api.enums import VectorsEnum
from keyboards.params_searching_cve_menu import find_cve_markup

router = Router()

@router.callback_query(F.data == "pocs_by_keywords")
async def process_callback_pocs_by_keywords():
    """ TODO ЧАСТЬ МАКСА"""
    pass