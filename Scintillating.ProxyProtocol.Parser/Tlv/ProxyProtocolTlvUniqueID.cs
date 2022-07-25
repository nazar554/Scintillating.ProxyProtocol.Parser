﻿namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// The value of the type PP2_TYPE_UNIQUE_ID is an opaque byte sequence of up to
/// 128 bytes generated by the upstream proxy that uniquely identifies the connection.
/// </summary>
public class ProxyProtocolTlvUniqueID : ProxyProtocolTlv
{
    /// <summary>
    /// The maximum allowed length.
    /// </summary>
    public const int MaxLength = 128;

    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvUniqueID"/> class.
    /// </summary>
    /// <param name="value">The unique ID.</param>
    public ProxyProtocolTlvUniqueID(ReadOnlyMemory<byte> value)
        : base(ProxyProtocolTlvType.PP2_TYPE_UNIQUE_ID, GetLength(value))
    {
        Value = value;
    }

    internal ProxyProtocolTlvUniqueID(byte[] value)
        : base(ProxyProtocolTlvType.PP2_TYPE_UNIQUE_ID, value.Length)
    {
        Value = value;
    }

    private static int GetLength(ReadOnlyMemory<byte> value)
    {
        int length = value.Length;
        if (length > MaxLength)
        {
            ParserThrowHelper.ThrowInvalidUniqueId();
        }
        return length;
    }

    /// <summary>
    /// The unique ID.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}