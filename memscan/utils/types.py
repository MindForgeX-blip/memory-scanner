"""
memscan/utils/types.py — Value type conversion utilities.

Handles packing/unpacking values for memory read/write operations.
Supports integers (8/16/32/64 bit), floats, doubles, strings,
byte arrays, and booleans. Also handles hex input parsing.
"""

import struct
import ctypes
from enum import Enum


class DataType(Enum):
    """Supported data types for memory scanning."""
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    FLOAT = "float"
    DOUBLE = "double"
    STRING = "string"
    STRING_UTF16 = "string_utf16"
    BYTES = "bytes"
    BOOL = "bool"


# Map from string names to DataType enum
TYPE_MAP = {
    "int8": DataType.INT8,
    "int16": DataType.INT16,
    "int32": DataType.INT32,
    "int64": DataType.INT64,
    "uint8": DataType.UINT8,
    "uint16": DataType.UINT16,
    "uint32": DataType.UINT32,
    "uint64": DataType.UINT64,
    "float": DataType.FLOAT,
    "double": DataType.DOUBLE,
    "string": DataType.STRING,
    "string_utf16": DataType.STRING_UTF16,
    "bytes": DataType.BYTES,
    "bool": DataType.BOOL,
    # Aliases
    "int": DataType.INT32,
    "str": DataType.STRING,
    "utf16": DataType.STRING_UTF16,
    "byte": DataType.BYTES,
}


def parse_value(raw_value, dtype):
    """
    Parse a user-provided value string into bytes for the given data type.
    
    Supports hex input (0xDEADBEEF), decimal, float notation, etc.
    
    Args:
        raw_value: String representation of the value (e.g., "42", "0xFF", "3.14")
        dtype: DataType enum or string name
    
    Returns:
        bytes: The packed value ready for memory comparison/write
    """
    dtype = _resolve_type(dtype)
    
    # Handle hex input for integer types
    if isinstance(raw_value, str) and raw_value.startswith(("0x", "0X")):
        if dtype in (DataType.FLOAT, DataType.DOUBLE, DataType.STRING,
                     DataType.STRING_UTF16, DataType.BYTES, DataType.BOOL):
            raise ValueError(f"Hex value not supported for {dtype.value}")
        raw_value = int(raw_value, 16)
    
    try:
        if dtype == DataType.INT8:
            return struct.pack("<b", int(raw_value))
        elif dtype == DataType.INT16:
            return struct.pack("<h", int(raw_value))
        elif dtype == DataType.INT32:
            return struct.pack("<i", int(raw_value))
        elif dtype == DataType.INT64:
            return struct.pack("<q", int(raw_value))
        elif dtype == DataType.UINT8:
            return struct.pack("<B", int(raw_value))
        elif dtype == DataType.UINT16:
            return struct.pack("<H", int(raw_value))
        elif dtype == DataType.UINT32:
            return struct.pack("<I", int(raw_value))
        elif dtype == DataType.UINT64:
            return struct.pack("<Q", int(raw_value))
        elif dtype == DataType.FLOAT:
            return struct.pack("<f", float(raw_value))
        elif dtype == DataType.DOUBLE:
            return struct.pack("<d", float(raw_value))
        elif dtype == DataType.STRING:
            return str(raw_value).encode("ascii")
        elif dtype == DataType.STRING_UTF16:
            return str(raw_value).encode("utf-16-le")
        elif dtype == DataType.BYTES:
            return parse_bytes(raw_value)
        elif dtype == DataType.BOOL:
            if isinstance(raw_value, str):
                return struct.pack("<?", raw_value.lower() in ("true", "1", "yes"))
            return struct.pack("<?", bool(raw_value))
    except (struct.error, ValueError) as e:
        raise ValueError(f"Cannot convert '{raw_value}' to {dtype.value}: {e}")


def unpack_value(data, dtype):
    """
    Unpack raw bytes into a Python value for the given data type.
    
    Args:
        data: bytes to unpack
        dtype: DataType enum or string name
    
    Returns:
        The unpacked Python value (int, float, str, bool, or bytes)
    """
    dtype = _resolve_type(dtype)
    
    try:
        if dtype == DataType.INT8:
            return struct.unpack("<b", data[:1])[0]
        elif dtype == DataType.INT16:
            return struct.unpack("<h", data[:2])[0]
        elif dtype == DataType.INT32:
            return struct.unpack("<i", data[:4])[0]
        elif dtype == DataType.INT64:
            return struct.unpack("<q", data[:8])[0]
        elif dtype == DataType.UINT8:
            return struct.unpack("<B", data[:1])[0]
        elif dtype == DataType.UINT16:
            return struct.unpack("<H", data[:2])[0]
        elif dtype == DataType.UINT32:
            return struct.unpack("<I", data[:4])[0]
        elif dtype == DataType.UINT64:
            return struct.unpack("<Q", data[:8])[0]
        elif dtype == DataType.FLOAT:
            return struct.unpack("<f", data[:4])[0]
        elif dtype == DataType.DOUBLE:
            return struct.unpack("<d", data[:8])[0]
        elif dtype == DataType.STRING:
            return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        elif dtype == DataType.STRING_UTF16:
            return data.split(b"\x00\x00", 1)[0].decode("utf-16-le", errors="replace")
        elif dtype == DataType.BYTES:
            return data.hex()
        elif dtype == DataType.BOOL:
            return struct.unpack("<?", data[:1])[0]
    except (struct.error, ValueError) as e:
        raise ValueError(f"Cannot unpack data as {dtype.value}: {e}")


def type_size(dtype):
    """
    Return the byte size of a data type.
    
    Args:
        dtype: DataType enum or string name
    
    Returns:
        int: size in bytes (0 for variable-length types like STRING)
    """
    dtype = _resolve_type(dtype)
    sizes = {
        DataType.INT8: 1, DataType.UINT8: 1,
        DataType.INT16: 2, DataType.UINT16: 2,
        DataType.INT32: 4, DataType.UINT32: 4,
        DataType.INT64: 8, DataType.UINT64: 8,
        DataType.FLOAT: 4,
        DataType.DOUBLE: 8,
        DataType.BOOL: 1,
        DataType.STRING: 0,       # variable
        DataType.STRING_UTF16: 0, # variable
        DataType.BYTES: 0,        # variable
    }
    return sizes.get(dtype, 0)


def parse_bytes(raw):
    """
    Parse a hex byte string like "89 45 FC ?? 8B 45" into bytes.
    
    Wildcards (?? or *) are represented as None in the result list.
    
    Args:
        raw: hex string with spaces, may contain ?? or * wildcards
    
    Returns:
        list of int or None (None = wildcard)
    
    Raises:
        ValueError: if a token is not a valid hex byte or wildcard
    """
    result = []
    parts = raw.strip().split()
    for p in parts:
        if p in ("??", "*", "?"):
            result.append(None)  # wildcard
        else:
            try:
                val = int(p, 16)
                if val < 0 or val > 255:
                    raise ValueError(f"Byte value out of range: {p}")
                result.append(val)
            except ValueError:
                raise ValueError(
                    f"Invalid AOB pattern byte: '{p}'. "
                    "Use hex bytes (00-FF) separated by spaces, wildcards as ??. "
                    f"Full pattern: '{raw}'"
                )
    return result


def parse_address(addr_str):
    """
    Parse an address string (hex or decimal) into an integer.
    
    Args:
        addr_str: "0x7FF123456789" or "140694289557385"
    
    Returns:
        int: the address
    """
    if isinstance(addr_str, int):
        return addr_str
    s = str(addr_str).strip()
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    return int(s)


def _resolve_type(dtype):
    """Resolve a string type name to a DataType enum."""
    if isinstance(dtype, DataType):
        return dtype
    if isinstance(dtype, str):
        dt = TYPE_MAP.get(dtype.lower())
        if dt:
            return dt
    raise ValueError(f"Unknown data type: {dtype}")
