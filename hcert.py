#!/usr/bin/env python3

import argparse
import base64
import binascii
import json
import logging
import time
import zlib
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

import base45
import cbor2
import cose.algorithms
import cose.curves
import cose.headers
import cose.keys.keyops
import qrcode
import qrcode.image.pil
import qrcode.image.svg
from aztec_code_generator import AztecCode
from cose.keys.cosekey import CoseKey
from cose.keys.ec2 import EC2
from cose.messages import CoseMessage
from cose.messages.sign1message import Sign1Message
from cryptojwt.jwk import JWK
from cryptojwt.jws.jws import JWS
from cryptojwt.jwx import key_from_jwk_dict
from cryptojwt.utils import b64d, b64e

SIGN_ALG = cose.algorithms.Es256
CONTENT_TYPE_CWT = 61

logger = logging.getLogger(__name__)


class CwtClaims(Enum):
    ISS = 1
    SUB = 2
    AUD = 3
    EXP = 4
    NBF = 5
    IAT = 6
    CTI = 7
    HCERT = -65537


class HealthCertificateClaims(Enum):
    EU_HCERT_V1 = 1


def read_cosekey(filename: str, private: bool = True) -> CoseKey:
    """Read key and return CoseKey"""
    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)
    return cosekey_from_jwk_dict(jwk_dict, private)


def cosekey_from_jwk_dict(jwk_dict: Dict, private: bool = True) -> CoseKey:
    """Create CoseKey from JWK dictionary"""

    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")

    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    if private:
        key = EC2(
            crv=cose.curves.P256,
            x=b64d(jwk_dict["x"].encode()),
            y=b64d(jwk_dict["y"].encode()),
            d=b64d(jwk_dict["d"].encode()),
        )
        key.key_ops = [cose.keys.keyops.SignOp, cose.keys.keyops.VerifyOp]
    else:
        key = EC2(
            crv=cose.curves.P256,
            x=b64d(jwk_dict["x"].encode()),
            y=b64d(jwk_dict["y"].encode()),
        )
        key.key_ops = [cose.keys.keyops.VerifyOp]
    if "kid" in jwk_dict:
        key.kid = jwk_dict["kid"].encode()
    return key


def read_jwk(filename: str, private: bool = True) -> JWK:
    """Read key and return JWK"""
    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)
    return key_from_jwk_dict(jwk_dict)


def json_compact_dumps(data) -> int:
    """Return JSON compact dumps"""
    return json.dumps(data, indent=None, separators=(",", ":"))


def json_compact_len(data) -> int:
    """Return length of JSON compact encoding"""
    return len(json_compact_dumps(data))


def encode_data(data: bytes, encoding: str) -> bytes:
    if encoding == "binary":
        return data
    elif encoding == "base45":
        return base45.b45encode(data)
    elif encoding == "base64":
        return base64.b64encode(data)
    elif encoding == "base85":
        return base64.b85encode(data)
    else:
        raise RuntimeError("Invalid encoding")


def decode_data(data: bytes, encoding: str) -> bytes:
    if encoding == "binary":
        return data
    elif encoding == "base45":
        return base45.b45decode(data)
    elif encoding == "base64":
        return base64.b64decode(data)
    elif encoding == "base85":
        return base64.b85decode(data)
    else:
        raise RuntimeError("Invalid encoding")


def sign_cwt(
    private_key: CoseKey,
    alg: cose.algorithms.CoseAlgorithm,
    hcert: Dict,
    kid: str = None,
    issuer: Optional[str] = None,
    ttl: Optional[int] = None,
) -> bytes:
    """Sign HCERT payload and return CWT"""

    protected_header = {
        cose.headers.Algorithm: alg,
        cose.headers.ContentType: CONTENT_TYPE_CWT,
        cose.headers.KID: kid.encode(),
    }
    unprotected_header = {}
    logger.debug("Protected header: %s", protected_header)
    logger.debug("Unprotected header: %s", unprotected_header)

    now = int(time.time())
    payload = {
        CwtClaims.ISS.value: issuer,
        CwtClaims.IAT.value: now,
        CwtClaims.EXP.value: now + ttl,
        CwtClaims.HCERT.value: {HealthCertificateClaims.EU_HCERT_V1.value: hcert},
    }
    payload = cbor2.dumps(payload)
    logger.info("CBOR-encoded payload: %d bytes", len(payload))

    cose_msg = Sign1Message(phdr=protected_header, payload=payload)
    cose_msg.key = private_key
    cwt = cose_msg.encode()
    logger.info("Raw signed CWT: %d bytes", len(cwt))

    return cwt


def sign_jwt(
    private_key: JWK,
    alg: str,
    hcert: Dict,
    kid: str = None,
    issuer: Optional[str] = None,
    ttl: Optional[int] = None,
) -> bytes:
    """Sign HCERT payload and return JWT"""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "iat": now,
        "exp": now + ttl,
        "hcert": hcert,
    }
    message = json_compact_dumps(payload)
    logger.info("JSON payload for JWT: %d bytes", len(message))
    res = str(JWS(message, alg=alg).sign_compact(keys=[private_key])).encode()
    logger.info("Raw signed JWT: %d bytes", len(res))
    return res


def verify_cwt(public_key: CoseKey, signed_data: bytes) -> Optional[Dict]:
    """Verify CWT and return HCERT payload"""

    cose_msg: Sign1Message = CoseMessage.decode(signed_data)
    logger.debug("Protected header: %s", cose_msg.phdr)
    logger.debug("Unprotected header: %s", cose_msg.uhdr)

    cose_msg.key = public_key
    if not cose_msg.verify_signature():
        raise RuntimeError("Bad signature")

    decoded_payload = cbor2.loads(cose_msg.payload)

    now = int(time.time())

    if (iss := decoded_payload.get(CwtClaims.ISS.value)) is not None:
        logger.info("Signatured issued by: %s", iss)

    if (iat := decoded_payload.get(CwtClaims.IAT.value)) is not None:
        logger.info("Signatured issued at: %s", datetime.fromtimestamp(iat))

    if (exp := decoded_payload.get(CwtClaims.EXP.value)) is not None:
        if exp > now:
            logger.info("Signatured expires at: %s", datetime.fromtimestamp(exp))
        else:
            logger.info("Signatured expired at: %s", datetime.fromtimestamp(exp))
            raise RuntimeError("Signature expired")

    hcert = decoded_payload.get(CwtClaims.HCERT.value)

    if (eu_hcert_v1 := hcert.get(HealthCertificateClaims.EU_HCERT_V1.value)) :
        return eu_hcert_v1

    logger.error("No EU HCERT version 1 found in CWT")
    return None


def command_sign(args: argparse.Namespace):
    """Create signed EHC"""

    key = read_cosekey(args.key, private=True)

    with open(args.input, "rt") as input_file:
        input_data = input_file.read()

    logger.info("Input JSON data: %d bytes", len(input_data))

    hcert_data = json.loads(input_data)
    logger.info("Compact JSON: %d bytes", json_compact_len(hcert_data))

    cwt = sign_cwt(
        private_key=key,
        alg=SIGN_ALG,
        kid=args.kid,
        hcert=hcert_data,
        issuer=args.issuer,
        ttl=args.ttl,
    )

    compressed_cwt = zlib.compress(cwt)
    logger.info("Compressed CWT: %d bytes", len(compressed_cwt))

    encoded_compressed_cwt = encode_data(compressed_cwt, args.encoding)
    logger.info(
        "Encoded compressed CWT: %d bytes (%s)",
        len(encoded_compressed_cwt),
        args.encoding,
    )

    # sign with JWS for comparison
    jwk = read_jwk(args.key, private=True)
    signed_data_jwt = sign_jwt(
        private_key=jwk,
        alg="ES256",
        kid=args.kid,
        hcert=hcert_data,
        issuer=args.issuer,
        ttl=args.ttl,
    )

    compressed_jwt = zlib.compress(signed_data_jwt)
    logger.info("Compressed JWT: %d bytes", len(compressed_jwt))
    encoded_compressed_jwt = encode_data(compressed_jwt, args.encoding)
    logger.info(
        "Encoded compressed JWT: %d bytes (%s)",
        len(encoded_compressed_jwt),
        args.encoding,
    )

    if args.output:
        with open(args.output, "wb") as output_file:
            output_file.write(cwt)
    else:
        logger.info("Output: %s", binascii.hexlify(cwt).decode())

    if args.aztec:
        AztecCode(encoded_compressed_cwt).save(args.aztec, 4)

    if args.qrcode:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=4,
            border=4,
        )
        if args.qrcode.endswith(".png"):
            image_factory = qrcode.image.pil.PilImage
        elif args.qrcode.endswith(".svg"):
            image_factory = qrcode.image.svg.SvgImage
        else:
            raise ValueError("Unknown QRcode image format")
        qr.add_data(encoded_compressed_cwt)
        qr.make(fit=True)
        img = qr.make_image(image_factory=image_factory)
        with open(args.qrcode, "wb") as qr_file:
            img.save(qr_file)


def command_verify(args: argparse.Namespace):
    """Verify signed EHC"""

    key = read_cosekey(args.key, private=False)
    with open(args.input, "rb") as input_file:
        encoded_data = input_file.read()

    if args.decode:
        compressed_data = decode_data(encoded_data, args.encoding)
        cwt = zlib.decompress(compressed_data)
    else:
        cwt = encoded_data

    payload = verify_cwt(public_key=key, signed_data=cwt)
    if args.output:
        with open(args.output, "wt") as output_file:
            json.dump(payload, output_file, indent=4)
    else:
        logger.info("Verified payload: %s", json.dumps(payload, indent=4))


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="Electronic Health Certificate signer")

    parser.add_argument(
        "--encoding",
        metavar="encoding",
        help="Transport encoding",
        choices=["binary", "base45", "base64", "base85"],
        default="base45",
        required=False,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
        required=False,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_sign = subparsers.add_parser("sign", help="Sign health cert")
    parser_sign.set_defaults(func=command_sign)
    parser_sign.add_argument(
        "--key", metavar="filename", help="Private JWK filename", required=True
    )
    parser_sign.add_argument(
        "--issuer",
        metavar="issuer",
        help="Signature issuer",
        required=False,
    )
    parser_sign.add_argument(
        "--kid", metavar="kid", help="Key identifier", required=False
    )
    parser_sign.add_argument(
        "--ttl",
        metavar="seconds",
        help="Signature TTL",
        type=int,
        required=False,
    )
    parser_sign.add_argument(
        "--input",
        metavar="filename",
        help="JSON-encoded payload",
        required=True,
    )
    parser_sign.add_argument(
        "--output",
        metavar="filename",
        help="Compressed CBOR output",
        required=False,
    )
    parser_sign.add_argument(
        "--aztec",
        metavar="filename",
        help="Aztec output",
        required=False,
    )
    parser_sign.add_argument(
        "--qrcode",
        metavar="filename",
        help="QR output",
        required=False,
    )

    parser_verify = subparsers.add_parser("verify", help="Verify signed cert")
    parser_verify.set_defaults(func=command_verify)
    parser_verify.add_argument(
        "--key", metavar="filename", help="Public JWK filename", required=True
    )
    parser_verify.add_argument(
        "--input",
        metavar="filename",
        help="Compressed CBOR input",
        required=True,
    )
    parser_verify.add_argument(
        "--output",
        metavar="filename",
        help="JSON-encoded payload",
        required=False,
    )
    parser_verify.add_argument(
        "--decode",
        metavar="filename",
        help="Decode data before processing",
        required=False,
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    args.func(args)


if __name__ == "__main__":
    main()
