# Тут будут клавы для меню
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton


#buttons
inline_btn_menu = InlineKeyboardButton(text="Меню", callback_data="menu_btn")
inline_btn_back_to_menu = InlineKeyboardButton(text="Вернуться в Меню", callback_data="menu_btn")
inline_btn_most_valuable_cve = InlineKeyboardButton(text="Значимые CVE", callback_data="valuable_cve")
inline_btn_find_cve = InlineKeyboardButton(text="Поиск CVE", callback_data="find_cve")
inline_btn_subscribe_on_news = InlineKeyboardButton(text="Подписка на новости выхода CVE", callback_data="subscribe_on_news")

#murkups
greetings_markup =  InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_menu]
    ]
)

main_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_find_cve, inline_btn_most_valuable_cve],
        [inline_btn_subscribe_on_news]
    ]
)
