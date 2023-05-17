import logging as log

from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from api.searchsploit.searchsploit import get_urls_list
from config import config
from forms import FindCVEGroup
from keyboards.main_menu import main_markup
from messages.pocs_output import get_pocs_links_text

router = Router()


@router.callback_query(F.data == "pocs_by_keywords")
async def process_callback_pocs_by_keywords(callback_query: CallbackQuery, state: FSMContext):
    await callback_query.message.edit_text("Введите ключевой параметр")
    await state.set_state(FindCVEGroup.find_poc_by_name)

    pass


@router.message(FindCVEGroup.find_poc_by_name)
async def adding_id(message: Message, state: FSMContext):
    inserted_keyword: str = message.text
    inserted_keyword = inserted_keyword.strip()

    if len(inserted_keyword) < 2:
        await message.answer('Слишком короткий запрос')
        return
    try:
        result_cve_list = get_urls_list(inserted_keyword)

        if len(result_cve_list) == 0:
            raise ValueError()

        if len(result_cve_list) > config.show_searchsploit:
            await message.answer(
                f'⚠ Результат слишком большой, поэтому я вывел только {config.show_searchsploit} ссылок ⚠')
            pass

        result_cve_list = result_cve_list[:config.show_searchsploit]

        await message.answer(get_pocs_links_text(result_cve_list))

    except ValueError as e:
        await message.answer(
            f"⚠ Не найдено PoC ⚠"
        )
    except Exception as e:
        log.warning(f'[adding_id] FAIL e={e}')

        await message.answer(
            f"Ошибка выполнения запроса 😢"
        )
        pass

    await message.answer(
        f"Меню",
        reply_markup=main_markup
    )
