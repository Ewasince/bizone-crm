import os

import telebot
from dotenv import load_dotenv

BOT_TOKEN = os.environ.get('BOT_API_KEY')

bot = telebot.TeleBot(BOT_TOKEN)


@bot.message_handler(commands=['start', 'hello'])
def send_welcome(message):
    bot.reply_to(message, "Howdy, how are you doing?")
    pass


@bot.message_handler(func=lambda msg: True)
def echo_all(message):
    bot.reply_to(message, message.text)
    pass


if __name__ == '__main__':
    bot.infinity_polling()
    pass
