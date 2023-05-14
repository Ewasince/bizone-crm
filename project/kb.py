# Тут будут клавы для меню
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


#menu buttons
inline_btn_menu = InlineKeyboardButton(text="Меню", callback_data="menu_btn")
inline_btn_back_to_menu = InlineKeyboardButton(text="Вернуться в Меню", callback_data="menu_btn")
inline_btn_find_by_id = InlineKeyboardButton(text="CVE по Id", callback_data="find_cve_by_id")
inline_btn_most_valuable_cve = InlineKeyboardButton(text="Значимые CVE", callback_data="valuable_cve")
inline_btn_find_cve_web = InlineKeyboardButton(text="CVE по параметрам (web)", callback_data="find_cve_web")
inline_btn_find_cve_tg = InlineKeyboardButton(text="CVE по параметрам (tg)", callback_data="find_cve_tg")
inline_btn_subscribe_on_news = InlineKeyboardButton(text="Подписка на новости выхода CVE", callback_data="subscribe_on_news")

#find CVE menu buttons
inline_btn_product = InlineKeyboardButton(text="Название продукта", callback_data="find_cve_name")
inline_btn_start_date = InlineKeyboardButton(text="Начальная дата", callback_data="find_cve_start_date")
inline_btn_end_date = InlineKeyboardButton(text="Конечная дата", callback_data="find_cve_end_date")
inline_btn_cvss = InlineKeyboardButton(text="CVSS", callback_data="find_cve_cvss")
inline_btn_vector = InlineKeyboardButton(text="Вектор", callback_data="find_cve_vector")
inline_btn_complexity= InlineKeyboardButton(text="Сложность", callback_data="find__cve_complexity")
inline_btn_find_cve_submit = InlineKeyboardButton(text="Найти CVE по заданным параметрам", callback_data="find_cve_submit")

inline_btn_cvss_v2 = InlineKeyboardButton(text="CVSS v2", callback_data="find_cve_cvss_v2")
inline_btn_cvss_v3 = InlineKeyboardButton(text="CVSS v3", callback_data="find_cve_cvss_v3")

inline_btn_back_cve_menu = InlineKeyboardButton(text="Вернуться к выбору параметров CVE", callback_data="find_cve_back")

inline_btn_cvss_v2_low = InlineKeyboardButton(text="Low", callback_data="find_cve_cvss_v2_low")
inline_btn_cvss_v2_medium = InlineKeyboardButton(text="Medium", callback_data="find_cve_cvss_v2_medium")
inline_btn_cvss_v2_high = InlineKeyboardButton(text="High", callback_data="find_cve_cvss_v2_hight")

inline_btn_cvss_v3_none = InlineKeyboardButton(text="None", callback_data="find_cve_cvss_v3_none")
inline_btn_cvss_v3_low = InlineKeyboardButton(text="Low", callback_data="find_cve_cvss_v3_low")
inline_btn_cvss_v3_medium = InlineKeyboardButton(text="Medium", callback_data="find_cve_cvss_v3_medium")
inline_btn_cvss_v3_hight = InlineKeyboardButton(text="High", callback_data="find_cve_cvss_v3_hight")
inline_btn_cvss_v3_critical = InlineKeyboardButton(text="Critical", callback_data="find_cve_cvss_v3_critical")

#most valuable CVE buttons
inline_btn_day = InlineKeyboardButton(text="За сутки", callback_data="most_valuable_day")
inline_btn_week = InlineKeyboardButton(text="За неделю", callback_data="most_valuable_week")
inline_btn_month = InlineKeyboardButton(text="За месяц", callback_data="most_valuable_month")
inline_btn_year = InlineKeyboardButton(text="За год", callback_data="most_valuable_year")


#murkups
greetings_markup =  InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_menu]
    ]
)

main_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_find_by_id],
        [inline_btn_find_cve_tg, inline_btn_find_cve_web],
        [inline_btn_most_valuable_cve],
        [inline_btn_subscribe_on_news]
    ]
)

find_cve_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_find_cve_submit],
        [inline_btn_product],
        [inline_btn_start_date, inline_btn_end_date],
        [inline_btn_cvss],
        [inline_btn_vector, inline_btn_complexity],
        [inline_btn_back_to_menu]
    ]
)

most_valuable_cve_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_day, inline_btn_week],
        [inline_btn_month, inline_btn_year],
        [inline_btn_back_to_menu]
    ]
)

find_cve_cvss_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_cvss_v2, inline_btn_cvss_v3],
        [inline_btn_back_cve_menu]
    ]
)

cvss_v2_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_cvss_v2_low],
        [inline_btn_cvss_v2_medium],
        [inline_btn_cvss_v2_high],
        []
    ]
)

