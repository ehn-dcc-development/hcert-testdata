"""Base45 encoding for QR Codes"""

QR_ALPHANUM_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
PY_ALPHANUM_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI"


def int2str(num, alphabet):
    """Encode a positive number into Base X and return the string.

    Arguments:
    - `num`: The number to encode
    - `alphabet`: The alphabet to use for encoding
    """
    if num == 0:
        return alphabet[0]
    arr = []
    arr_append = arr.append  # Extract bound-method for faster access.
    _divmod = divmod  # Access to locals is faster.
    base = len(alphabet)
    while num:
        num, rem = _divmod(num, base)
        arr_append(alphabet[rem])
    arr.reverse()
    return "".join(arr)


def str2int(string, alphabet):
    """Decode a Base X encoded string into the number

    Arguments:
    - `string`: The encoded string
    - `alphabet`: The alphabet to use for decoding
    """
    base = len(alphabet)
    strlen = len(string)
    num = 0

    idx = 0
    for char in string:
        power = strlen - (idx + 1)
        num += alphabet.index(char) * (base ** power)
        idx += 1

    return num


def base45encode(b: bytes, charset: str = QR_ALPHANUM_CHARSET) -> str:
    """Convert bytes to base45-encoded string"""
    i = int.from_bytes(b, byteorder="big")
    return int2str(i, charset)


def base45decode(s: str, charset: str = QR_ALPHANUM_CHARSET) -> bytes:
    """Decode base45-encoded string to bytes"""
    i = str2int(s, charset)
    l = (i.bit_length() + 7) // 8
    return i.to_bytes(length=l, byteorder="big")
