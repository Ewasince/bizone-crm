from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from api.nist_api.enums import VectorsEnumPresent
from keyboards.cvss_menu import inline_btn_back_cve_menu

# Adjacent Network (AV:A)

# Buttons
from messages.cve_output import RU_NAMES_VECTOR

inline_btn_vector_local = InlineKeyboardButton(
    text=RU_NAMES_VECTOR[VectorsEnumPresent.LOCAL.value],
    callback_data="vector_local"
)

inline_btn_vector_adj_network = InlineKeyboardButton(
    text=RU_NAMES_VECTOR[VectorsEnumPresent.ADJACENT_NETWORK.value],
    callback_data="vector_adj_network"
)

inline_btn_vector_network = InlineKeyboardButton(
    text=RU_NAMES_VECTOR[VectorsEnumPresent.NETWORK.value],
    callback_data="vector_network"
)

# Markups
vector_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_vector_local],
        [inline_btn_vector_adj_network],
        [inline_btn_vector_network],
        [inline_btn_back_cve_menu]
    ]
)