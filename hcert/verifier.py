import argparse
import json
import logging
import time
from datetime import datetime

from cryptojwt.utils import b64d, b64e

from hcert.cli import HCERT_CLAIM, HealthCertificateClaims
from hcert.cwt import CWT, CwtClaims, cosekey_from_jwk_dict
from hcert.optical import decode_and_decompress
from hcert.scanner import AccessIsAtr110

logger = logging.getLogger(__name__)

DEFAULT_SCANNER_PORT = "/dev/tty.usbmodem1143101"


def process_hc1_cwt(signed_data: bytes, public_keys):
    now = int(time.time())
    cwt = CWT.from_bytes(signed_data=signed_data, public_keys=public_keys)

    if (iss := cwt.claims.get(CwtClaims.ISS.value)) is not None:
        logger.info("Signatured issued by: %s", iss)

    logger.info("Signature verified by: %s", b64e(cwt.key.kid).decode())

    if (iat := cwt.claims.get(CwtClaims.IAT.value)) is not None:
        logger.info("Signatured issued at: %s", datetime.fromtimestamp(iat))

    if (exp := cwt.claims.get(CwtClaims.EXP.value)) is not None:
        if exp > now:
            logger.info("Signatured expires at: %s", datetime.fromtimestamp(exp))
        else:
            logger.info("Signatured expired at: %s", datetime.fromtimestamp(exp))
            raise RuntimeError("Signature expired")

    hcert = cwt.claims.get(HCERT_CLAIM)
    eu_hcert_v1 = hcert.get(HealthCertificateClaims.EU_HCERT_V1.value)

    if eu_hcert_v1 is None:
        logger.error("No EU HCERT version 1 found in CWT")
        return

    logger.info("Verified payload: %s", json.dumps(eu_hcert_v1, indent=4))


def main():
    parser = argparse.ArgumentParser(
        description="Electronic Health Certificate Optical Verifier"
    )
    parser.add_argument(
        "--port",
        metavar="port",
        help="Scanner serial port",
        default=DEFAULT_SCANNER_PORT,
    )
    parser.add_argument(
        "--jwks", metavar="filename", help="JWKS filename", required=True
    )
    parser.add_argument("--input", metavar="filename", help="Raw input filename")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug output",
        required=False,
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    public_keys = []

    with open(args.jwks) as jwks_file:
        jwks = json.load(jwks_file)
        for jwk_dict in jwks.get("keys", []):
            key = cosekey_from_jwk_dict(jwk_dict, private=False)
            key.kid = b64d(jwk_dict["kid"].encode())
            public_keys.append(key)

    if args.input:
        with open(args.input, "rb") as input_file:
            data = input_file.read()
            process_hc1_cwt(data, public_keys)
        return

    scanner = AccessIsAtr110(port=args.port)
    print("Waiting for data from scanner...")
    while True:
        data = scanner.read()
        if data:
            s = data.decode()
            if s.startswith("HC1"):
                signed_data = decode_and_decompress(data[3:])
                process_hc1_cwt(signed_data, public_keys)
        time.sleep(1)


if __name__ == "__main__":
    main()
