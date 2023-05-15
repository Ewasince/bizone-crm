from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from datetime import datetime

from cve_api import aget_cve_by_id
from forms import FindCVEGroup

from config import config

import logging as log

import kb

router = Router()


@router.callback_query(F.data == "find_cve_tg")
async def process_callback_find_cve(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu handler
    '''
    user_data = await state.get_data()

    await callback_query.message.answer(f"Параметры запроса поиска: {user_data}", reply_markup=kb.find_cve_markup)


@router.callback_query(F.data == "find_cve_by_id")
async def process_callback_add_id(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu: handler for the button that adds the CVE`s id parameter
    '''
    await callback_query.message.edit_text("Введите Id")
    await state.set_state(FindCVEGroup.id)


@router.message(FindCVEGroup.id)
async def adding_id(message: Message, state: FSMContext):
    inserted_id: str = message.text

    # try:
    #     inserted_id = int(inserted_id)
    # except Exception as e:
    #     log.debug(e)
    #     return await message.answer(
    #         "Неверное значение Id, попробуйте еще раз",
    #         reply_markup=kb.main_markup
    #     )

    try:

        result_cve_list = await aget_cve_by_id(inserted_id)

        if len(result_cve_list) != 1:
            raise Exception("Wrong number of cve!")
            pass

        result_cve = result_cve_list[0]

    except Exception as e:
        log.warning(f'[adding_id] FAIL e={e}')
        return
        pass

    await message.answer(f'''
По данному id найдена информация :
        
🔵 Номер CVE <a href='{result_cve.link}'>{result_cve.id}</a>
🔵 Дата/время регистрации CVE {result_cve.date}
🔵 Описание CVE {result_cve.description}
        
🔵 CVSSv2 {result_cve.cvss2}
🔵 CVSSv3 {result_cve.cvss3}
        
🔵 Уровень критичности {result_cve.score}
🔵 Вектор атаки {result_cve.vector}
🔵 Сложность атаки {result_cve.complexity}
🔵 EPSS рейтинг {result_cve.epss}
        
🔵 Продукт/вендор для которого характерна CVE {result_cve.product}
🔵 Уязвимые версии продукта {result_cve.versions}
        
🔵 PoC/CVE WriteUp (С кликабельными ссылками, если есть) {result_cve.poc}
🔵 Информация о количестве упоминаний {result_cve.mentions}
🔵 Необходимые действия по устранению уязвимости {result_cve.elimination if result_cve.elimination else 'вовремя обновиться'}
'''
    )

    await message.answer(
        f"Меню",
        reply_markup=kb.main_markup
    )


@router.callback_query(F.data == "find_cve_name")
async def process_callback_add_product_name(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu: Handler for the button that adds the product name parameter
    '''
    await callback_query.message.edit_text("Введите название")
    await state.set_state(FindCVEGroup.product)


@router.message(FindCVEGroup.product)
async def addiing_product_name(message: Message, state: FSMContext):
    inserted_name = message.text

    await state.update_data(product=inserted_name)

    user_data = await state.get_data()

    await message.answer(
        f"Название продукта установлено. Теперь данные: {user_data}",
        reply_markup=kb.find_cve_markup
    )


@router.callback_query(F.data == "find_cve_start_date")
async def process_callback_add_start_date(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu: Handler for the button that adds the start date parameter
    '''
    await callback_query.message.edit_text("Введите начальную дату в формате 'dd.mm.yyyy'")
    await state.set_state(FindCVEGroup.start_date)


@router.message(FindCVEGroup.start_date)
async def addiing_start_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        datetime.strptime(inserted_date, "%d.%m.%Y")

        await state.update_data(start_date=inserted_date)

    except ValueError as e:
        log.debug(e)

        user_data = await state.get_data()

        return await message.answer(
            f"Неправильный формат ввода даты, попробуйте еще раз",
            reply_markup=kb.find_cve_markup
        )

    user_data = await state.get_data()

    await message.answer(
        f"Начальная дата установлена. Теперь данные: {user_data}",
        reply_markup=kb.find_cve_markup
    )


@router.callback_query(F.data == "find_cve_end_date")
async def process_callback_add_end_date(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu: Handler for the button that adds the end date parameter
    '''
    await callback_query.message.edit_text("Введите конечную дату в формате 'dd.mm.yyyy'")
    await state.set_state(FindCVEGroup.end_date)


@router.message(FindCVEGroup.end_date)
async def addind_end_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        datetime.strptime(inserted_date, "%d.%m.%Y")

        await state.update_data(start_date=inserted_date)

    except ValueError as e:
        log.debug(e)

        user_data = await state.get_data()

        return await message.answer(
            f"Неправильный формат ввода даты, попробуйте еще раз",
            reply_markup=kb.find_cve_markup
        )

    user_data = await state.get_data()

    await message.answer(
        f"Конечная дата установлена. Теперь данные: {user_data}",
        reply_markup=kb.find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss")
async def process_callback_add_cvss(callback_query: CallbackQuery, state: FSMContext):
    '''
        find_cve_menu: Handler for the button that adds the CVSS parameter
    '''
    await callback_query.message.edit_text(
        "Какую версию CVSS вы хотите использовать",
        reply_markup=kb.find_cve_cvss_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v2")
async def process_callback_add_cvss_v2(callback_query: CallbackQuery, state: FSMContext):
    '''
        cvss_menu: Handler for the button that selects version v2
    '''
    await callback_query.message.edit_text(
        "Выберите значие:",
        reply_markup=kb.cvss_v2_markup
    )
