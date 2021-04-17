import requests

from config.google_config import GOOGLE_DISCOVERY_URL

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()