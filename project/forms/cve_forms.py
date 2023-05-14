from aiogram.fsm.state import State, StatesGroup


class FindCVEGroup(StatesGroup):
    id = State()
    cvss_v2 = State()
    cvss_v3 = State()
    vector = State()
    complexity = State()
    start_date = State()
    end_date = State()
    product = State()
