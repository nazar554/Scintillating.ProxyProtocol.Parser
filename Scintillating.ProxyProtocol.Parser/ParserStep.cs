﻿namespace Scintillating.ProxyProtocol.Parser;

internal enum ParserStep : sbyte
{
    Invalid = -1,
    Initial,
    PreambleV1,
    AddressFamilyV2,
    LocalV2,
    TlvV2,
    Done,
}