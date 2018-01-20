import json

import requests
import time

from oauth2client.service_account import ServiceAccountCredentials

from service import settings


def _get_access_token():
    """Retrieve a valid access token that can be used to authorize requests.

    :return: Access token.
    """
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
        json.loads(settings.FCM_CREDENTIALS), settings.FCM_SCOPE)
    access_token_info = credentials.get_access_token()
    return access_token_info.access_token


def _request_headers():
    return {
        "Content-Type": "application/json; UTF-8",
        "Authorization": "Bearer " + _get_access_token(),
    }


def build_message(topic, data):
    return {
        "message": {
            "topic": topic,
            "data": data
        }
    }


def do_request(payload, timeout=None):
    response = requests.post(settings.FCM_END_POINT, headers=_request_headers(), data=json.dumps(payload),
                             timeout=timeout)
    if 'Retry-After' in response.headers and int(response.headers['Retry-After']) > 0:
        sleep_time = int(response.headers['Retry-After'])
        time.sleep(sleep_time)
        return do_request(payload, timeout)
    return response.json()
