import binascii
import json

import requests
from coincurve import PublicKey
from coincurve.utils import hex_to_bytes
from sha3 import keccak_256

from service import settings


def _parse_owners(response):
    owner_list_data = response[130:]
    return [owner_list_data[i + 24:i + 64].lower() for i in range(0, len(owner_list_data), 64)]


def _build_get_owners_request(safe_address):
    return {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": "0x%s" % safe_address, "data": "0xa0e67e2b"}, "latest"]
    }


def load_owners(safe_address):
    # noinspection PyBroadException
    try:
        response = requests.post(settings.ETHEREUM_GATE, data=json.dumps(_build_get_owners_request(safe_address)))
        return _parse_owners(response.json()["result"])
    except Exception:
        return None


def _sha3(data: bytes) -> bytes:
    """
    Raises:
        RuntimeError: If Keccak lib initialization failed, or if the function
        failed to compute the hash.
        TypeError: This function does not accept unicode objects, they must be
        encoded prior to usage.
    """
    return keccak_256(data).digest()


def _publickey_to_address(publickey: bytes) -> bytes:
    return _sha3(publickey[1:])[12:]


def _recover_publickey(messagedata, signature, hasher=_sha3):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    signature = signature[:-1] + chr(signature[-1] - 27).encode()
    publickey = PublicKey.from_signature_and_message(
        signature,
        messagedata,
        hasher=hasher,
    )
    return publickey.format(compressed=False)


def get_sender(message, signature, hash=True):
    # noinspection PyBroadException
    try:
        return binascii.hexlify(
            _publickey_to_address(
                _recover_publickey(binascii.unhexlify(message), binascii.unhexlify(signature),
                                   _sha3 if hash else None))).lower().decode()
    except Exception:
        return None
