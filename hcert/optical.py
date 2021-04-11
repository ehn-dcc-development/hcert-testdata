import binascii
import logging
import zlib

import qrcode
import qrcode.image.pil
import qrcode.image.svg
import qrcode.util
from aztec_code_generator import AztecCode

from .utils import decode_data, encode_data

logger = logging.getLogger(__name__)


def compress_and_encode(data: bytes, encoding: str = "base45") -> bytes:
    compressed_data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
    encoded_data = encode_data(compressed_data, encoding)
    encoded_compressed_data = "HC1".encode() + encoded_data
    logger.debug(
        "Uncompressed data: %d bytes, %s",
        len(data),
        binascii.hexlify(data).decode(),
    )
    logger.debug(
        "Compressed data: %d bytes, %s",
        len(compressed_data),
        binascii.hexlify(compressed_data).decode(),
    )
    logger.debug(
        "Encoded compressed data: %d bytes, %s",
        len(encoded_compressed_data),
        binascii.hexlify(encoded_compressed_data).decode(),
    )
    print(encoded_compressed_data)
    return encoded_compressed_data


def decode_and_decompress(data: bytes, encoding: str = "base45") -> bytes:
    decoded_data = decode_data(data, encoding)
    decompressed_data = zlib.decompress(decoded_data)
    logger.debug(
        "Uncompressed data: %d bytes, %s",
        len(decompressed_data),
        binascii.hexlify(decompressed_data).decode(),
    )
    return decompressed_data


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
    qr.add_data(qr_data, optimize=0)
    assert qr.data_list[0].mode == qrcode.util.MODE_ALPHA_NUM
    qr.make(fit=True)
    img = qr.make_image(image_factory=image_factory)
    with open(filename, "wb") as qr_file:
        img.save(qr_file)
    logger.info("Wrote %d bytes as QR to %s", len(qr_data), filename)
