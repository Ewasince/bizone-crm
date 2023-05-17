from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

# Buttons 
inline_btn_vendor = InlineKeyboardButton(
    text="Название вендора",
    callback_data="find_cve_vendor"
)

inline_btn_product = InlineKeyboardButton(
    text="Название продукта",
    callback_data="find_cve_name"
)

inline_btn_start_date = InlineKeyboardButton(
    text="Начальная дата",
    callback_data="find_cve_start_date"
)

inline_btn_end_date = InlineKeyboardButton(
    text="Конечная дата",
    callback_data="find_cve_end_date"
)

inline_btn_cvss = InlineKeyboardButton(
    text="CVSS",
    callback_data="find_cve_cvss"
)

inline_btn_vector = InlineKeyboardButton(
    text="Вектор",
    callback_data="find_cve_vector"
)

inline_btn_complexity = InlineKeyboardButton(
    text="Сложность",
    callback_data="find_cve_complexity"
)

inline_btn_find_cve_submit = InlineKeyboardButton(
    text="Найти CVE по заданным параметрам",
    callback_data="find_cve_submit"
)

inline_btn_back_to_menu = InlineKeyboardButton(
    text="🔙 Вернуться в Меню",
    callback_data="menu_btn"
)

# Murkups

find_cve_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_find_cve_submit],
        [inline_btn_vendor, inline_btn_product],
        [inline_btn_start_date, inline_btn_end_date],
        [inline_btn_cvss],
        [inline_btn_vector, inline_btn_complexity],
        [inline_btn_back_to_menu]
    ]
)
