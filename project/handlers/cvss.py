from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.nist_api.enums import CvssVerEnum, CvssSeverityV2Enum, CvssSeverityV3Enum
from keyboards.cvss_menu import find_cve_cvss_markup, cvss_v2_markup, cvss_v3_markup
from keyboards.params_searching_cve_menu import find_cve_markup

router = Router()


@router.callback_query(F.data == "find_cve_cvss_v2")
async def process_callback_add_cvss_v2(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that selects version v2
    """
    await state.update_data(cvss_version=CvssVerEnum.VER2.value, cvss_param=None)

    await callback_query.message.edit_text(
        "Выберите значие:",
        reply_markup=cvss_v2_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3")
async def process_callback_add_cvss_v3(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that selects version v3
    """
    await state.update_data(cvss_version=CvssVerEnum.VER3.value, cvss_param=None)

    await callback_query.message.edit_text(
        "Выберите значие:",
        reply_markup=cvss_v3_markup
    )


@router.callback_query(F.data == "find_cve_back")
async def process_callback_back_to_cve(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that returns to the cve menu of parameterized search cves
    """
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Параметры запроса поиска: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_back_cvss")
async def process_callback_back_to_cvss(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that returns to the cvss version selection
    """
    await state.update_data(cvss_param=None)
    await callback_query.message.edit_text(
        "Какую версию CVSS вы хотите использовать",
        reply_markup=find_cve_cvss_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v2_low")
async def process_callback_svss_v2_low(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss parameter to LOW
    """

    await state.update_data(cvss_param=[CvssSeverityV2Enum.LOW.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v2_medium")
async def process_callback_cvss_v2_medium(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss parameter to MEDIUM
    """

    await state.update_data(cvss_param=[CvssSeverityV2Enum.MEDIUM.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v2_high")
async def process_callback_svss_v2_high(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss parameter to HIGH
    """

    await state.update_data(cvss_param=[CvssSeverityV2Enum.HIGH.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3_none")
async def process_callback_svss_v3_none(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss v3 parameter to NONE
    """

    await state.update_data(cvss_param=None)
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3_low")
async def process_callback_svss_v3_low(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss v3 parameter to LOW
    """

    await state.update_data(cvss_param=[CvssSeverityV3Enum.LOW.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3_medium")
async def process_callback_svss_v3_medium(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss v3 parameter to MEDIUM
    """

    await state.update_data(cvss_param=[CvssSeverityV3Enum.MEDIUM.value])
    user_data = await  state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3_high")
async def process_callback_svss_v3_high(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss parameter to HIGH
    """

    await state.update_data(cvss_param=[CvssSeverityV3Enum.HIGH.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )


@router.callback_query(F.data == "find_cve_cvss_v3_critical")
async def process_callback_svss_v3_critical(callback_query: CallbackQuery, state: FSMContext):
    """
        cvss_menu: Handler for the button that set cvss v3 parameter to CRITICAL
    """

    await state.update_data(cvss_param=[CvssSeverityV3Enum.CRITICAL.value])
    user_data = await state.get_data()

    await callback_query.message.edit_text(
        f"Главное меню, Параметры на данный момент: {user_data}",
        reply_markup=find_cve_markup
    )
