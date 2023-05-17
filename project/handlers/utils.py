MAX_TEXT_LENGTH = 4096

tags_list = ['a',
             'i',
             'b',
             'code',
             's',
             'u',
             'pre',
             ]


async def answer_decorator(message, text, **kwargs):
    # text = kwargs.pop('text')
    texts = [text]
    # new_text = ''

    if len(text) > 4096:
        texts = []

        while len(text) > 0:
            # prepare_text = text[:MAX_TEXT_LENGTH]
            #
            # str.rfind
            split_pos = MAX_TEXT_LENGTH
            if len(text) > MAX_TEXT_LENGTH:
                split_pos = text.rfind('\n', 0, MAX_TEXT_LENGTH)
            # if split_pos == -1:
            #     split_pos =
            new_text = text[:split_pos]
            text = text[split_pos:]

            flag, o_tag, c_tag = find_tags(new_text)
            if flag:
                # o_tag = new_text.rfind('\n')
                t1 = new_text[:o_tag]
                texts.append(t1)

                t2 = new_text[o_tag:]
                text = t2 + text
                continue
                pass

            texts.append(new_text)
            text = text.strip()
        pass

    for t in texts:
        await message.answer(t, **kwargs)
        pass

    pass


def find_tags(text: str) -> (bool, int, int):
    for t in tags_list:
        open_tag = f'<{t}'
        o_tag = text.rfind(open_tag)

        close_tag = f'</{t}'
        c_tag = text.rfind(close_tag)

        if o_tag > 0 and c_tag == -1:
            return True, o_tag, c_tag
            pass

        if c_tag < o_tag:
            return True, o_tag, c_tag
            pass
        pass

    return False, None, None

# def split_by_tag(text, pos: int):
