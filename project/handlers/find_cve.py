import logging as log
from typing import Dict, Any

import dateutil.parser as isoparser
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import Message, CallbackQuery

from api.api_facade import get_cve_repo
from config import config
from forms import FindCVEGroup
from keyboards.complexity_menu import complexity_markup
from keyboards.cvss_menu import find_cve_cvss_markup
from keyboards.main_menu import main_markup
from keyboards.params_searching_cve_menu import find_cve_markup
from keyboards.vector_menu import vector_markup
from messages.cve_output import get_cve_by_id_output_text, get_params_text

router = Router()


@router.message(FindCVEGroup.id)
async def adding_id(message: Message, state: FSMContext):
    inserted_id: str = message.text

    cve_repo = get_cve_repo(None)

    try:

        result_cve_list = await cve_repo.a_get_cve_by_id(inserted_id)

        if len(result_cve_list) != 1:
            raise Exception("Wrong number of cve!")
            pass

        result_cve = result_cve_list[0]

    except Exception as e:
        log.warning(f'[adding_id] FAIL e={e}')
        return
        pass

    await message.answer(get_cve_by_id_output_text(result_cve))

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
    user_data: Dict[str, str] = await state.get_data()

    params_text = get_params_text(user_data)

    await message.answer(
        f"Название вендора успешно установлено. Установленные параметры :{params_text}",
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

    params_text = get_params_text(user_data)

    await message.answer(
        f"Название продукта установлено. Установленные параметры: {params_text}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_start_date")
async def process_callback_add_start_date(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the start date parameter
    """
    await callback_query.message.edit_text(
        "Введите начальную дату в формате 'yyyy-mm-dd'. Учтите, что период должен быть не больше 120 дней.")
    await state.set_state(FindCVEGroup.start_date)


@router.message(FindCVEGroup.start_date)
async def adding_start_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        isoparser.isoparse(inserted_date)

        await state.update_data(start_date=inserted_date)

    except ValueError as e:
        log.debug(e)

        return await message.answer(
            f"Неправильный формат ввода даты, попробуйте еще раз",
            reply_markup=find_cve_markup
        )

    user_data = await state.get_data()
    await state.set_state(FindCVEGroup.default_state)
    params_text = get_params_text(user_data)


    await message.answer(
        f"Начальная дата установлена. Установленные параметры: {params_text}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_end_date")
async def process_callback_add_end_date(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button that adds the end date parameter
    """
    await callback_query.message.edit_text(
        "Введите конечную дату в формате 'yyyy-mm-dd'. Учтите, что период должен быть не больше 120 дней.")
    await state.set_state(FindCVEGroup.end_date)


@router.message(FindCVEGroup.end_date)
async def addind_end_date(message: Message, state: FSMContext):
    inserted_date = message.text

    try:
        isoparser.isoparse(inserted_date)

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
    params_text = get_params_text(user_data)


    await message.answer(
        f"Конечная дата установлена. Установленные параметры: {params_text}",
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
async def process_callback_cve_submit(callback_query: CallbackQuery, state: FSMContext):
    """
        find_cve_menu: Handler for the button submit params of cve and do request for api
    """
    request_params_raw: Dict[str, Any] = await state.get_data()

    log.debug(f'[process_callback_cve_submit] request_params_raw={request_params_raw}')

    result_list = []

    # request_params = request_params_raw

    request_params = {}
    request_params['vendor'] = request_params_raw["vendor"]
    request_params['product'] = request_params_raw["product"]
    request_params['date'] = (request_params_raw["start_date"], request_params_raw["end_date"])
    request_params['cvss_version'] = request_params_raw["cvss_version"]
    request_params['cvss_param'] = request_params_raw["cvss_param"]
    request_params['vector'] = request_params_raw["vector"]
    request_params['complexity'] = request_params_raw["complexity"]

    cve_repo = get_cve_repo(request_params['cvss_version'])

    try:
        result_list = await cve_repo.a_get_cve_by_params(
            vendor=request_params['vendor'],
            product=request_params['product'],
            date=request_params['date'],
            cvss=request_params['cvss_param'],
            vector=request_params['vector'],
            complexity=request_params['complexity'],
            epss=None,
            qm=None,
            mentions=None
        )
    except Exception as e:
        log.warning(f"[cve_submit] {e}")
        pass

    if len(result_list) > config.max_cve_output:
        await callback_query.message.answer(
            text='Найденных CVE слишком много, я выведу только первые пять'
        )

        # get_cve_by_id_output_text(result_cve)

    print(len(result_list))
    for cve in result_list[:config.max_cve_output]:
        await callback_query.message.answer(
            text=get_cve_by_id_output_text(cve)
        )

    await callback_query.message.answer(
        text="Меню:",
        reply_markup=main_markup
    )
