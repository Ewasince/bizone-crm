from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from params_searching_cve_menu import inline_btn_back_to_menu

# Buttons
inline_btn_day = InlineKeyboardButton(
    text="За сутки",
    callback_data="most_valuable_day"
)

inline_btn_week = InlineKeyboardButton(
    text="За неделю",
    callback_data="most_valuable_week"
)

inline_btn_month = InlineKeyboardButton(
    text="За месяц",
    callback_data="most_valuable_month"
)

inline_btn_year = InlineKeyboardButton(
    text="За год",
    callback_data="most_valuable_year"
)

# Markups
most_valuable_cve_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_day, inline_btn_week],
        [inline_btn_month, inline_btn_year],
        [inline_btn_back_to_menu]
    ]
)
