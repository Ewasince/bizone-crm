from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from keyboards.params_searching_cve_menu import inline_btn_back_to_menu

# Buttons
inline_btn_day = InlineKeyboardButton(
    text="За сутки",
    callback_data="most_valuable_day"
)

inline_btn_week = InlineKeyboardButton(
    text="За неделю",
    callback_data="most_valuable_week"
)

# Markups
most_valuable_cve_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_day, inline_btn_week],
        [inline_btn_back_to_menu]
    ]
)
