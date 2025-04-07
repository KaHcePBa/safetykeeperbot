import asyncio
import logging

from aiogram import Bot, Dispatcher

from config.config import settings
from handlers import vt_router

# import os

# Settings with dynaconf
dynaconf_settings = settings
BOT_TOKEN = dynaconf_settings.BOT_APIKEY

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Settings with os.getenv
# BOT_TOKEN = os.getenv("BOT_TOKEN")
# VT_API_KEY = os.getenv("VT_API_KEY")
# DEBUG = os.getenv('DEBUG', 'true').lower() == 'true'
# if os.getenv('ENVIRONMENT') == 'heroku':
#     DEBUG = False
# bot = Bot(token=os.getenv('BOT_TOKEN'))

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG,
    filename='bot.log'
)
logging.info('Start running...')


# Запуск бота
async def main():
    dp = Dispatcher()
    # Connect Router. If I create a new Router, I add it here. I can also disable them here.
    dp.include_routers(vt_router)

    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nThe program was interrupted by the user (Ctrl+C).")
    except asyncio.CancelledError:
        print("\nThe asynchronous task was canceled.")
    except Exception as e:
        print(f"\nThere's been a mistake: {e}")
    finally:
        print("Job completion.")
