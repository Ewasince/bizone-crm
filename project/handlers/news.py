# from aiogram import Router, F
# from aiogram.fsm.context import FSMContext
# from aiogram.types import CallbackQuery
# from api.api_facade import get_cve_repo
# from datetime import datetime
# from db import check_cve, insert_value

# import logging as log


# router = Router()


# router.callback_query("news")
# async def show_news(callback_query: CallbackQuery):
#     cur_date = str(datetime.now().date())
#     result_list = []
#     cve_repo = get_cve_repo('3')

#     try:
#         result_list = await cve_repo.a_get_cve_by_params(
#                 vendor=None
#                 product=None
#                 date=(cur_date,None)
#                 cvss=None
#                 vector=None,
#                 complexity=None,
#                 epss=None,
#                 qm=None,
#                 mentions=None
#             )
#     except Exception as e:
#         log.warning(f"[show_news] {e}")

#     for i in result_list():
#         if
