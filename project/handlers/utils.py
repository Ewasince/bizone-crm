MAX_TEXT_LENGTH = 4096


async def answer_decorator(message, text, **kwargs):
    # text = kwargs.pop('text')
    texts = [text]

    if len(text) > 4096:
        texts = [text[i:i + MAX_TEXT_LENGTH] for i in range(0, len(text), MAX_TEXT_LENGTH)]
        pass

    for t in texts:
        await message.answer(t, **kwargs)
        pass
