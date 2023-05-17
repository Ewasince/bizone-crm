from aiogram.fsm.state import State, StatesGroup


class FindCVEGroup(StatesGroup):
    default_state = State()
    id = State()
    vendor = State()
    product = State()
    start_date = State()
    end_date = State()
    product_version = State()
    find_poc_by_name = State()
