import telebot
import requests
import tldextract
import os

from phishing_checker import score_domain

bot = telebot.TeleBot('')

PHISHTANK_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz'
PHISHTANK_FILE = 'ALL-phishing-domains.txt'

def download_phishtank():
    response = requests.get(PHISHTANK_URL, stream=True)
    with open(PHISHTANK_FILE, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)


def load_phishtank():
    if not os.path.exists(PHISHTANK_FILE):
        download_phishtank()

    with open(PHISHTANK_FILE, 'rb') as f:
        content = f.read().decode('latin-1')
    return set(content.splitlines())

phishtank_domains = load_phishtank()
print("Обновление систем безопасности завершено")
@bot.message_handler(commands=['check'])
def check_phishing(message):
    try:
        url = message.text.split()[1]
    except IndexError:
        bot.send_message(message.chat.id, 'Пожалуйста, введите ссылку для проверки!')
        return

    domain = tldextract.extract(url).registered_domain
    score = score_domain(url)
    percentage = round((score/240)*100, 0)
    if domain in phishtank_domains:
        bot.send_message(message.chat.id, '❌ Данная ссылка является фишинговой ❌\n\n❗️ Никогда не вводите свои личные данные на подозрительных сайтах ❗️')
    elif score > 180:
        bot.send_message(message.chat.id, f'⚠️ Ссылка {url} имеет высокий риск быть фишинговой! Рекомендуется быть осторожным. Вероятность фишинга: {percentage}% ⚠️\n\n❗️ Никогда не вводите свои личные данные на подозрительных сайтах ❗️')
    elif score > 60:
        bot.send_message(message.chat.id, f'🔍 Ссылка {url} имеет умеренный риск быть фишинговой. Рекомендуется быть внимательным. Вероятность фишинга: {percentage}% 🔎\n\n💡 Переходите на сайты только из надежных источников, если не уверены в ссылке, попросите помощи у знающих людей 💡')
    else:
        bot.send_message(message.chat.id, f'✅ Ссылка {url} не является фишинговой ✅\n\nВероятность фишинга: {percentage}% 🔎\n\n👍 Пользуйтесь Интернетом безопасно и уверенно 👍')
bot.polling() 
