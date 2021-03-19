import logging
import zlib

import qrcode
import qrcode.image.pil
import qrcode.image.svg
from aztec_code_generator import AztecCode

from .utils import encode_data

logger = logging.getLogger(__name__)


def compress_and_encode(data: bytes, encoding: str = "base45") -> bytes:
    compressed_data = zlib.compress(data)
    encoded_compressed_data = encode_data(compressed_data, encoding)
    logger.debug("Compressed data: %d bytes", len(compressed_data))
    logger.debug("Encoded compressed data: %d bytes", len(encoded_compressed_data))
    return encoded_compressed_data


def save_aztec(payload: bytes, filename: str, encoding: str = "base45") -> None:
    """Save CWT as Aztec"""
    logger.info("Encoding %d bytes for Aztec", len(payload))
    aztec_data = compress_and_encode(payload, encoding)
    AztecCode(aztec_data).save(filename, 4)
    logger.info("Wrote %d bytes as Aztec to %s", len(aztec_data), filename)


def save_qrcode(payload: bytes, filename: str, encoding: str = "base45") -> None:
    """Save CWT as QR Code"""
    logger.info("Encoding %d bytes for QR", len(payload))
    qr_data = compress_and_encode(payload, encoding)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=4,
        border=4,
    )
    if filename.endswith(".png"):
        image_factory = qrcode.image.pil.PilImage
    elif filename.endswith(".svg"):
        image_factory = qrcode.image.svg.SvgImage
    else:
        raise ValueError("Unknown QRcode image format")
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=image_factory)
    with open(filename, "wb") as qr_file:
        img.save(qr_file)
    logger.info("Wrote %d bytes as QR to %s", len(qr_data), filename)
