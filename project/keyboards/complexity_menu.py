from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from api.nist_api.enums import ComplexityEnum
from keyboards.cvss_menu import inline_btn_back_cve_menu
# Buttons
from messages.cve_output import RU_NAMES_COMPLEXITY

inline_btn_complexity_low = InlineKeyboardButton(
    text=RU_NAMES_COMPLEXITY[ComplexityEnum.LOW.value],
    callback_data="complexity_low"
)

inline_btn_complexity_medium = InlineKeyboardButton(
    text=RU_NAMES_COMPLEXITY[ComplexityEnum.MEDIUM.value],
    callback_data="complexity_medium"
)

inline_btn_complexity_high = InlineKeyboardButton(
    text=RU_NAMES_COMPLEXITY[ComplexityEnum.HIGH.value],
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
