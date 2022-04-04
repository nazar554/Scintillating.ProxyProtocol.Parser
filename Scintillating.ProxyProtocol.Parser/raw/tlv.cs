﻿namespace Scintillating.ProxyProtocol.Parser.raw;

internal enum tlv : byte
{
    PP2_TYPE_ALPN = 0x01,
    PP2_TYPE_AUTHORITY = 0x02,
    PP2_TYPE_CRC32C = 0x03,
    PP2_TYPE_NOOP = 0x04,
    PP2_TYPE_UNIQUE_ID = 0x05,
    PP2_TYPE_SSL = 0x20,
    PP2_SUBTYPE_SSL_VERSION = 0x21,
    PP2_SUBTYPE_SSL_CN = 0x22,
    PP2_SUBTYPE_SSL_CIPHER = 0x23,
    PP2_SUBTYPE_SSL_SIG_ALG = 0x24,
    PP2_SUBTYPE_SSL_KEY_ALG = 0x25,
    PP2_TYPE_NETNS = 0x30,

    PP2_TYPE_MIN_CUSTOM = 0xE0,
    PP2_TYPE_MAX_CUSTOM = 0xEF,

    PP2_TYPE_MIN_EXPERIMENT = 0xF0,
    PP2_TYPE_MAX_EXPERIMENT = 0xF7,

    PP2_TYPE_MIN_FUTURE = 0xF8,
    PP2_TYPE_MAX_FUTURE = 0xFF,
}