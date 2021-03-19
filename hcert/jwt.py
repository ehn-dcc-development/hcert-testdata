import json
import logging
import time
from typing import Dict, Optional

from cryptojwt.jwk import JWK
from cryptojwt.jws.jws import JWS
from cryptojwt.jwx import key_from_jwk_dict

from .utils import json_compact_dumps

logger = logging.getLogger(__name__)


def read_jwk(filename: str, private: bool = True) -> JWK:
    """Read key and return JWK"""
    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)
    return key_from_jwk_dict(jwk_dict)


def sign_jwt(
    private_key: JWK,
    alg: str,
    hcert: Dict,
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
