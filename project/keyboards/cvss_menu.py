from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

# Buttons
inline_btn_cvss_v2 = InlineKeyboardButton(
    text="CVSS v2", callback_data="find_cve_cvss_v2"
)
inline_btn_cvss_v3 = InlineKeyboardButton(
    text="CVSS v3", callback_data="find_cve_cvss_v3"
)

inline_btn_back_cve_menu = InlineKeyboardButton(
    text="Вернуться к выбору параметров CVE",
    callback_data="find_cve_back"
)

inline_btn_back_cvss_menu = InlineKeyboardButton(
    text="Вернуть к выбору версии SVSS",
    callback_data="find_cve_back_cvss"
)

inline_btn_cvss_v2_low = InlineKeyboardButton(
    text="Low", callback_data="find_cve_cvss_v2_low"
)
inline_btn_cvss_v2_medium = InlineKeyboardButton(
    text="Medium", callback_data="find_cve_cvss_v2_medium"
)
inline_btn_cvss_v2_high = InlineKeyboardButton(
    text="High", callback_data="find_cve_cvss_v2_high"
)


inline_btn_cvss_v3_low = InlineKeyboardButton(
    text="Low", callback_data="find_cve_cvss_v3_low"
)
inline_btn_cvss_v3_medium = InlineKeyboardButton(
    text="Medium", callback_data="find_cve_cvss_v3_medium"
)
inline_btn_cvss_v3_high = InlineKeyboardButton(
    text="High", callback_data="find_cve_cvss_v3_high"
)
inline_btn_cvss_v3_critical = InlineKeyboardButton(
    text="Critical", callback_data="find_cve_cvss_v3_critical"
)

# Markups
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
        [inline_btn_back_cvss_menu]
    ]
)

cvss_v3_markup = InlineKeyboardMarkup(
    inline_keyboard=[
        [inline_btn_cvss_v3_low],
        [inline_btn_cvss_v3_medium],
        [inline_btn_cvss_v3_high],
        [inline_btn_cvss_v3_critical],
        [inline_btn_back_cvss_menu]
    ]
)
