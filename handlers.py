from aiogram import Router, types

from app import URL_PATTERN, check_url_vt, ensure_protocol, is_valid_url

vt_router = Router()


@vt_router.message()
async def auto_check_url(message: types.Message):
    # Skip command messages
    if message.text and message.text.startswith("/"):
        return

    # Looking for links in message.entities (hidden hyperlinks)
    urls = []
    if message.entities:
        for entity in message.entities:
            if entity.type == "text_link" and entity.url:
                urls.append(entity.url)

    # If there are no links in the entities, look for the URL in the text
    if not urls and message.text:
        urls = URL_PATTERN.findall(message.text)

    # If there are no links, we do nothing
    if not urls:
        return

    # Process only the first link found
    url = urls[0]
    # Add a protocol if it does not exist
    url_with_protocol = ensure_protocol(url)

    if not is_valid_url(url_with_protocol):
        await message.reply(f"Найден некорректный URL: {url}. Убедитесь, что это действительная ссылка.")
        return

    await message.reply(f"Обнаружена ссылка {url_with_protocol}. Проверяю на VirusTotal...")
    await check_url_vt(url_with_protocol, message)
