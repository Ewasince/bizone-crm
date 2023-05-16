from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from keyboards.cvss_menu import inline_btn_back_cve_menu

# Buttons
inline_btn_complexity_low = InlineKeyboardButton(
    text="Low",
    callback_data="complexity_low"
)

inline_btn_complexity_medium = InlineKeyboardButton(
    text="Medium",
    callback_data="complexity_medium"
)

inline_btn_complexity_high = InlineKeyboardButton(
    text="High",
    callback_data="complexity_high"
)

# Markups
complexity_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_complexity_low],
        [inline_btn_complexity_medium],
        [inline_btn_complexity_high],
        [inline_btn_back_cve_menu]
    ]
)
