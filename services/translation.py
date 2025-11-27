
import json
import os

LOCALES_DIR = os.path.join(os.path.dirname(__file__), "../locales")
translations = {}


# function for load_translations
def load_translations():
    translations.clear()
    for lang_file in os.listdir(LOCALES_DIR):
        if lang_file.endswith(".json"):
            lang_code = lang_file.split(".")[0]
            with open(os.path.join(LOCALES_DIR, lang_file), "r", encoding="utf-8") as f:
                translations[lang_code] = json.load(f)

load_translations()  # Auto-load on startup


# function for translate message 
def translate_message(message: str, lang: str = "en", **kwargs) -> str:
    template = translations.get(lang, {}).get(message, message)
    try:
        return template.format(**kwargs)
    except KeyError:
        return template
