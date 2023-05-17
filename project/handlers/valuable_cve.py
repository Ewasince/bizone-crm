import logging as log

from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from api.api_facade import get_cve_repo
from handlers.utils import answer_decorator
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

        if len(result) == 0:
            raise ValueError()

    except ValueError as e:
        await answer_decorator(callback_query.message,
                               f"⚠ Не найдено CVE ⚠"
                               )
    except Exception as e:
        log.warning(f'[procress_callback_most_valuable_day] FAIL e={e}')

        await answer_decorator(callback_query.message,
                               f"Ошибка выполнения запроса 😢"
                               )
        pass

    for i in range(len(result)):
        await answer_decorator(callback_query.message,
                               text=get_trends_cve_output_text(result[i], i)
                               )

    await answer_decorator(callback_query.message,
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

            if len(result) == 0:
                raise ValueError()

        except ValueError as e:
            await answer_decorator(callback_query.message,
                                   f"⚠ Не найдено CVE ⚠"
                                   )
        except Exception as e:
            log.warning(f'[procress_callback_most_valuable_week] FAIL e={e}')

            await answer_decorator(callback_query.message,
                                   f"Ошибка выполнения запроса 😢"
                                   )
            pass

        for i in range(len(result)):
            await answer_decorator(callback_query.message,
                                   text=get_trends_cve_output_text(result[i], i)
                                   )

        await answer_decorator(callback_query.message,
                               text="Меню",
                               reply_markup=main_markup
                               )
