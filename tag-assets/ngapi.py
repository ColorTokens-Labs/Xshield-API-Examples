#
#  Helper functions to compute the signature and header for the Xshield APIs
#  ColorTokens Inc.
#  

import json
import base64

from datetime import datetime
from urllib.parse import urlparse

# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Load configuration from file
with open('config.json') as config_file:
    config = json.load(config_file)

keyConfig = config["keyConfig"]
# Read values from configuration
tenant_id = config['tenantId']
user_id = config['userId']
fingerprint = keyConfig['fingerprint']
private_key_location = keyConfig['privateKey']
passphrase = keyConfig['passphrase']

if not tenant_id:
    raise ValueError("Tenancy ID (tenantId) config field not set")
if not user_id:
    raise ValueError("User ID (userId) config field not set")
if not fingerprint:
    raise ValueError(
        "Key Fingerprint (keyConfig.fingerprint) config field not set")
if not private_key_location:
    raise ValueError(
        "Private Key (keyConfig.privateKeyBase64) config field not set")

api_key_id = f"{tenant_id}::{user_id}::{fingerprint}"

methodsThatRequireExtraHeaders = ["POST", "PUT", "PATCH"]


def base64encode(str, withPadding=False):
    encoded = base64.b64encode(str)
    result = encoded if withPadding else encoded.rstrip(b"=")
    return result.decode()


def create_signature(url, method, headers, body=None):
    # Current date
    current_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Extract host from URL
    parsed_url = urlparse(url)
    host = parsed_url.hostname

    path_with_query = parsed_url.path + "?" + \
        parsed_url.query if parsed_url.query else parsed_url.path

    # Signing String
    signing_string_array = [
        f"(request-target): {method.lower()} {path_with_query}",
        f"date: {current_date}",
        f"host: {host}"
    ]

    headers_to_sign = [
        "(request-target)",
        "date",
        "host"
    ]

    if method in methodsThatRequireExtraHeaders:
        body = body if body else 'nil'
        body_b64 = base64encode(bytes(body, 'utf-8'), True)

        body_hash = SHA256.new(bytes(body_b64, 'utf-8'))
        base64_encoded_body_hash = base64encode(body_hash.digest(), True)
        signing_string_array.append(
            f"x-content-sha256: {base64_encoded_body_hash}")
        headers_to_sign.append("x-content-sha256")
        headers["x-content-sha256"] = base64_encoded_body_hash

    # Signature Calculation
    signing_string = "\n".join(signing_string_array)

    # Load private key
    try:
        with open(private_key_location, 'r') as file:
            # Read the contents of the file
            private_key_string = file.read()

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Key not found at location {private_key_location}")

    private_key = RSA.import_key(
        private_key_string, passphrase=passphrase if passphrase else None)

    # Sign
    h = SHA256.new(signing_string.encode('utf-8'))
    signature = pss.new(private_key).sign(h)

    # Encode
    encoded_signature = base64encode(signature)
    auth_header_value = f'Signature version="1",keyId="{api_key_id}",algorithm="rsa-sha256",headers="{" ".join(headers_to_sign)}",signature="{encoded_signature}"'

    # Add the Authorization header with the calculated signature
    headers[
        "Authorization"] = auth_header_value
    headers["host"] = host
    headers["date"] = current_date

    return headers
