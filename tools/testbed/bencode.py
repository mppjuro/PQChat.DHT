"""
Canonical Bencode Encoder & Decoder conforming to BitTorrent BEP 3 & BEP 44.
Strict canonical dictionary ordering, integer bounds, and binary string lengths.
"""

from typing import Any, Union, Dict, List, Tuple


class BencodeError(ValueError):
    """Raised when parsing invalid or non-canonical Bencoded data."""
    pass


def bencode(obj: Any) -> bytes:
    """Encodes a Python object into canonical Bencoded bytes."""
    if isinstance(obj, int) and not isinstance(obj, bool):
        return f"i{obj}e".encode("ascii")
    elif isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        return f"{len(b)}:".encode("ascii") + b
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        return f"{len(b)}:".encode("ascii") + b
    elif isinstance(obj, list):
        encoded_items = b"".join(bencode(item) for item in obj)
        return b"l" + encoded_items + b"e"
    elif isinstance(obj, dict):
        # Dictionary keys must be sorted by raw byte string ordering (BEP 3)
        items: List[Tuple[bytes, bytes]] = []
        for k, v in obj.items():
            if isinstance(k, str):
                k_bytes = k.encode("utf-8")
            elif isinstance(k, (bytes, bytearray)):
                k_bytes = bytes(k)
            else:
                raise BencodeError(f"Dictionary keys must be strings or bytes, got {type(k)}")
            items.append((k_bytes, bencode(v)))

        # Lexicographical sort on raw key bytes
        items.sort(key=lambda x: x[0])
        encoded_dict = bytearray(b"d")
        for k_bytes, v_encoded in items:
            encoded_dict.extend(f"{len(k_bytes)}:".encode("ascii"))
            encoded_dict.extend(k_bytes)
            encoded_dict.extend(v_encoded)
        encoded_dict.extend(b"e")
        return bytes(encoded_dict)
    else:
        raise BencodeError(f"Unsupported type for bencoding: {type(obj)}")


def bdecode(data: bytes) -> Any:
    """Decodes canonical Bencoded bytes into Python structures."""
    if not isinstance(data, (bytes, bytearray)):
        raise BencodeError("Input must be bytes")
    data = bytes(data)
    val, offset = _decode_stream(data, 0, len(data))
    if offset != len(data):
        raise BencodeError(f"Trailing unparsed bytes ({len(data) - offset} remaining)")
    return val


def _decode_stream(data: bytes, offset: int, length: int) -> Tuple[Any, int]:
    if offset >= length:
        raise BencodeError("Unexpected EOF in bencoded stream")

    char = data[offset:offset+1]

    if char == b"i":
        # Integer: i<num>e
        end = data.find(b"e", offset + 1)
        if end == -1:
            raise BencodeError("Unterminated bencoded integer")
        num_str = data[offset + 1:end].decode("ascii")
        if num_str == "-0" or (num_str.startswith("0") and len(num_str) > 1) or (num_str.startswith("-0")):
            raise BencodeError(f"Non-canonical integer representation: {num_str}")
        try:
            return int(num_str), end + 1
        except ValueError as exc:
            raise BencodeError(f"Invalid integer: {num_str}") from exc

    elif char == b"l":
        # List: l<items>e
        curr = offset + 1
        items = []
        while curr < length and data[curr:curr+1] != b"e":
            item, curr = _decode_stream(data, curr, length)
            items.append(item)
        if curr >= length or data[curr:curr+1] != b"e":
            raise BencodeError("Unterminated bencoded list")
        return items, curr + 1

    elif char == b"d":
        # Dict: d<key><val>...e
        curr = offset + 1
        res: Dict[Union[str, bytes], Any] = {}
        prev_key: Union[bytes, None] = None
        while curr < length and data[curr:curr+1] != b"e":
            # Key must be string/bytes
            colon = data.find(b":", curr)
            if colon == -1:
                raise BencodeError("Malformed dictionary key")
            len_str = data[curr:colon].decode("ascii")
            if not len_str.isdigit():
                raise BencodeError("Dictionary key length not a number")
            k_len = int(len_str)
            k_start = colon + 1
            k_end = k_start + k_len
            if k_end > length:
                raise BencodeError("Dictionary key exceeds buffer")
            key_bytes = data[k_start:k_end]

            if prev_key is not None and key_bytes <= prev_key:
                raise BencodeError("Non-canonical dictionary key ordering or duplicate key")
            prev_key = key_bytes

            curr = k_end
            val, curr = _decode_stream(data, curr, length)
            # Try to store as utf-8 string if valid, else bytes
            try:
                key_name = key_bytes.decode("utf-8")
                res[key_name] = val
            except UnicodeDecodeError:
                res[key_bytes] = val

        if curr >= length or data[curr:curr+1] != b"e":
            raise BencodeError("Unterminated bencoded dictionary")
        return res, curr + 1

    elif char in b"0123456789":
        # Byte string: <len>:<content>
        colon = data.find(b":", offset)
        if colon == -1:
            raise BencodeError("Malformed byte string prefix")
        len_str = data[offset:colon].decode("ascii")
        if not len_str.isdigit():
            raise BencodeError("Byte string length is not an integer")
        str_len = int(len_str)
        start = colon + 1
        end = start + str_len
        if end > length:
            raise BencodeError(f"Byte string length {str_len} exceeds available bytes")
        return data[start:end], end

    else:
        raise BencodeError(f"Invalid bencode prefix byte: {char}")


def encode_bep44_sign_data(v: bytes, seq: int, salt: Union[bytes, None] = None) -> bytes:
    """
    Encodes BEP 44 mutable data payload for signing (Bencode signData):
    Without salt: "3:seqi<seq>e1:v<len>:<v>"
    With salt: "4:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>"
    """
    out = bytearray()
    if salt is not None and len(salt) > 0:
        out.extend(b"4:salt")
        out.extend(f"{len(salt)}:".encode("ascii"))
        out.extend(salt)
    out.extend(b"3:seqi")
    out.extend(str(seq).encode("ascii"))
    out.extend(b"e1:v")
    out.extend(f"{len(v)}:".encode("ascii"))
    out.extend(v)
    return bytes(out)
