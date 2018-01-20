import string

from rest_framework.decorators import api_view
from rest_framework.response import Response

from service.push.fcm import do_request, build_message
from service.push.gnosis_safe import get_sender, load_owners

SIGN_REQUEST_PREFIX = 'gnosafe://sign_req'
SIGN_RESPONSE_PREFIX = 'gnosafe://sign_res'
HTTP_SENDER_SIGNATURE = 'HTTP_SENDER_SIGNATURE'


@api_view(["POST"])
def request_signature(request, safe_address):
    if len(safe_address) != 40 or not all(c in string.hexdigits for c in safe_address):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    uri = request.data.get("uri")
    if not uri:
        return Response({"error": "uri is required"}, 400)

    if not uri.startswith(SIGN_REQUEST_PREFIX):
        return Response({"error": "should be a sign request uri"}, 400)
    try:
        query_safe_address = dict(query_param.split("=") for query_param in uri.split("?")[1].split("&")).get("safe")[
                             2:]
    except IndexError:
        return Response({"error": "invalid uri"}, 400)

    if not query_safe_address or safe_address.lower() != query_safe_address.lower():
        return Response({"error": "safe incorrect in uri"}, 400)

    signature = request.META.get(HTTP_SENDER_SIGNATURE)
    if not signature:
        return Response({"error": "signature missing"}, 400)

    sender = get_sender(safe_address, request.META.get(HTTP_SENDER_SIGNATURE))
    if not sender:
        return Response({"error": "invalid sender"}, 400)

    owners = load_owners(safe_address)
    if not owners:
        return Response({"error": "could not load owners of safe"}, 400)

    if sender not in owners:
        return Response({"error": "sender not owner of safe"}, 400)

    owners.remove(sender)
    return Response(do_request(build_message("request_signature.%s" % safe_address.lower(),
                                             {"uri": uri, "targets": ','.join(owners)})))


@api_view(["POST"])
def send_signature(request, safe_address):
    if len(safe_address) != 40 or not all(c in string.hexdigits for c in safe_address):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    uri = request.data.get("uri")
    if not uri:
        return Response({"error": "uri is required"}, 400)

    if not uri.startswith(SIGN_RESPONSE_PREFIX):
        return Response({"error": "should be a sign response uri"}, 400)

    try:
        signature = uri.split("/")[-1]
    except IndexError:
        return Response({"error": "invalid uri"}, 400)

    tx_hash = request.data.get("hash")
    if not tx_hash:
        return Response({"error": "hash is required"}, 400)

    sender = get_sender(tx_hash, signature, False)
    if not sender:
        return Response({"error": "invalid sender"}, 400)

    owners = load_owners(safe_address)
    if not owners:
        return Response({"error": "could not load owners of safe"}, 400)

    if sender not in owners:
        return Response({"error": "sender not owner of safe"}, 400)

    return Response(do_request(build_message("respond_signature.%s" % safe_address.lower(), {"uri": uri})))
