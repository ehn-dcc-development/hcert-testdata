"""JWS verifier"""

import argparse
import json
import logging

from cryptojwt.jws.jws import JWS
from cryptojwt.jwx import key_from_jwk_dict
from cryptojwt.utils import b64d


def extract_headers(data: str) -> dict:
    """Extract JSON-encoded headers"""
    return json.loads(b64d(data.encode()).decode())


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="JWS verifier")

    parser.add_argument(
        "--trusted",
        dest="trusted",
        metavar="filename",
        help="Trusted keys (JWKS)",
        required=False,
    )
    parser.add_argument(
        "--input",
        dest="jws_input",
        metavar="filename",
        help="JWS file input",
        required=True,
    )
    parser.add_argument(
        "--output",
        dest="output",
        metavar="filename",
        help="Output",
        required=False,
    )
    parser.add_argument(
        "--headers",
        dest="headers_output",
        metavar="filename",
        help="Headers output",
        required=False,
    )
    parser.add_argument(
        "--debug", dest="debug", action="store_true", help="Enable debugging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    trusted_keys = []
    if args.trusted:
        with open(args.trusted) as input_file:
            trusted_payload = json.load(input_file)
            if isinstance(trusted_payload, dict):
                trusted_keys.append(key_from_jwk_dict(trusted_payload))
            elif isinstance(trusted_payload, dict):
                for jwk_dict in trusted_payload["keys"]:
                    trusted_keys.append(key_from_jwk_dict(jwk_dict, private=False))
            else:
                raise ValueError("Unknown trusted list format")

    with open(args.jws_input, "rt") as input_file:
        jws_file = input_file.read()

    protected_headers = []
    jws_dict = json.loads(jws_file)

    if args.trusted:
        jws = JWS()
        message = jws.verify_json(jws_file, keys=trusted_keys)
    else:
        message = json.loads(b64d(jws_dict["payload"].encode()).decode())

    for signatures in jws_dict["signatures"]:
        if "protected" in signatures:
            protected_headers.append(extract_headers(signatures["protected"]))

    if args.headers_output:
        with open(args.headers_output, "wt") as output_file:
            print(json.dumps(protected_headers, indent=4), file=output_file)
    else:
        if args.trusted:
            print("# JWS PROTECTED HEADERS (VERIFIED)")
        else:
            print("# JWS PROTECTED HEADERS (NOT VERIFIED)")
        print(json.dumps(protected_headers, indent=4, sort_keys=True))

    if args.output:
        with open(args.output, "wt") as output_file:
            print(json.dumps(message, indent=4), file=output_file)
    else:
        if args.trusted:
            print("# JWS CONTENTS (VERIFIED)")
        else:
            print("# JWS CONTENTS (NOT VERIFIED)")
        print(json.dumps(message, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
