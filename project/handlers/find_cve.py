from aiogram.types import Message, CallbackQuery
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from datetime import datetime
from typing import Dict

from api.cve_api import aget_cve_by_id
from forms import FindCVEGroup

import logging as log

from keyboards.params_searching_cve_menu import find_cve_markup
from keyboards.main_menu import main_markup
from keyboards.cvss_menu import find_cve_cvss_markup
from keyboards.vector_menu import vector_markup
from keyboards.complexity_menu import complexity_markup

router = Router()

# TODO верхний регист при вводе CVE
# TODO версия ПО


@router.message(FindCVEGroup.id)
async def adding_id(message: Message, state: FSMContext):
    inserted_id: str = message.text

    # try:
    #     inserted_id = int(inserted_id)
    # except Exception as e:
    #     log.debug(e)
    #     return await message.answer(
    #         "Неверное значение Id, попробуйте еще раз",
    #         reply_markup=main_markup
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
        reply_markup=main_markup
    )


@router.callback_query(F.data == "find_cve_vendor")
async def process_callback_add_vendor(callback_query: CallbackQuery, state: FSMContext):
    """
        find cve_menu: Handler for the button that adds the vendor parameter
    """
    await callback_query.message.edit_text("Введите название вендора")
    await state.set_state(FindCVEGroup.vendor)


@router.message(FindCVEGroup.vendor)
async def add_vendor(message: Message, state: FSMContext):
    input_vendor: str = message.text

    await state.update_data(vendor=input_vendor)

    await state.set_state(FindCVEGroup.default_state)
    user_date: Dict[str, str] = await state.get_data()

    await message.answer(
        f"Название вендора успешно установлено. Теперь данные: {user_date}",
        reply_markup=find_cve_markup
    ) 


@router.callback_query(F.data == "find_cve_name")
async def process_callback_add_product_name(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the product name parameter
    """
    await callback_query.message.edit_text("Введите название")
    await state.set_state(FindCVEGroup.product)


@router.message(FindCVEGroup.product)
async def addiing_product_name(message: Message, state: FSMContext):
    inserted_name = message.text

    await state.update_data(product=inserted_name)

    user_data = await state.get_data()
    await state.set_state(FindCVEGroup.default_state)

    await message.answer(
        f"Название продукта установлено. Теперь данные: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_start_date")
async def process_callback_add_start_date(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the start date parameter
    """
    await callback_query.message.edit_text("Введите начальную дату в формате 'dd.mm.yyyy'")
    await state.set_state(FindCVEGroup.start_date)


@router.message(FindCVEGroup.start_date)
async def adding_start_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        datetime.strptime(inserted_date, "%d.%m.%Y")

        await state.update_data(start_date=inserted_date)

    except ValueError as e:
        log.debug(e)

        user_data = await state.get_data()

        return await message.answer(
            f"Неправильный формат ввода даты, попробуйте еще раз",
            reply_markup=find_cve_markup
        )

    user_data = await state.get_data()
    await state.set_state(FindCVEGroup.default_state)

    await message.answer(
        f"Начальная дата установлена. Теперь данные: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_end_date")
async def process_callback_add_end_date(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the end date parameter
    """
    await callback_query.message.edit_text("Введите конечную дату в формате 'dd.mm.yyyy'")
    await state.set_state(FindCVEGroup.end_date)


@router.message(FindCVEGroup.end_date)
async def addind_end_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        datetime.strptime(inserted_date, "%d.%m.%Y")

        await state.update_data(end_date=inserted_date)

    except ValueError as e:
        log.debug(e)

        user_data = await state.get_data()

        return await message.answer(
            f"Неправильный формат ввода даты, попробуйте еще раз",
            reply_markup=find_cve_markup
        )

    user_data = await state.get_data()
    await state.set_state(FindCVEGroup.default_state)

    await message.answer(
        f"Конечная дата установлена. Теперь данные: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss")
async def process_callback_add_cvss(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the CVSS parameter
    """

    await callback_query.message.edit_text(
        "Какую версию CVSS вы хотите использовать",
        reply_markup=find_cve_cvss_markup
    )


@router.callback_query(F.data == "find_cve_vector")
async def process_callback_add_cvss(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the vector parameter
    """

    await callback_query.message.edit_text(
        "Каков вектор доступа?",
        reply_markup=vector_markup
    )


@router.callback_query(F.data == "find_cve_complexity")
async def process_callback_add_cvss(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the complexity parameter
    """

    await callback_query.message.edit_text(
        "Какова сложность доступа?",
        reply_markup=complexity_markup
    )


@router.callback_query(F.data == "find_cve_submit")
async def proccess_callback_cve_submit(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button submit params of cve and do request for api
    """
    request_params: Dict[str, str] = await state.get_data()

    """
        TODO ТУТ ЗАПРОС ПО ПАРАМЕТРАМ ФОРМАТ ПАРАМЕТРОВ МОЖЕМ ПОДОГНАТЬ ПОД API-ШКУ
        пока просто вывод параметров списком в сообщения
    """
    await callback_query.message.answer(
        f"Введенные параметры: {request_params}",
        reply_markup=main_markup
    )
    


