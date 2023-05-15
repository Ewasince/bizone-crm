from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from keyboards.cvss_menu import inline_btn_back_cve_menu

# Adjacent Network (AV:A)

# Buttons
inline_btn_vector_local = InlineKeyboardButton(
    text="Local",
    callback_data="vector_local"
)

inline_btn_vector_adj_network = InlineKeyboardButton(
    text="Adjacent Network",
    callback_data="vector_adj_network"
)

inline_btn_vector_network = InlineKeyboardButton(
    text="Network",
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