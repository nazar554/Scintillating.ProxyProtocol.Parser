using Scintillating.ProxyProtocol.Parser.raw;
using Scintillating.ProxyProtocol.Parser.Tlv;
using Scintillating.ProxyProtocol.Parser.Util;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using static Scintillating.ProxyProtocol.Parser.ProxyProtocolTlvType;

[module: SkipLocalsInit]

namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// PROXY Protocol header parser, supports partial headers, is re-usable.
/// </summary>
[StructLayout(LayoutKind.Auto)]
public struct ProxyProtocolParser
{
    private const AddressFamily AF_UNSPEC = AddressFamily.Unspecified;
    private const int TLV_STACKALLOC_THRESHOLD = 1024;

    // sizeof(raw.hdr_v2.sig) + sizeof(ver_cmd) + sizeof(fam) + sizeof(len) = 16
    internal const int len_v2 = (hdr_v2.sig_len + 2) * sizeof(byte) + sizeof(short);

    // "PROXY \r\n".Length = sizeof("PROXY") + sizeof((byte)' ') + sizeof("\r\n") = 8
    internal const int len_v1 = ParserConstants.PreambleV1Length + ParserConstants.DelimiterV1Length + sizeof(byte);

    private byte _proxyAddrLength;
    private int _bytesFilled;
    private hdr _raw_hdr;
    private ParserStep _step;

    /// <summary>
    /// Attempt to parse available data to internal parser state.
    /// </summary>
    /// <param name="sequence">Data to parse (can be partial).</param>
    /// <param name="advanceTo">Part of the sequence that was consumed/examined.</param>
    /// <param name="proxyProtocolHeader">The result if parsing succeeded.</param>
    /// <returns>true when parsing succeeded and finished, otherwise false.</returns>
    /// <exception cref="ProxyProtocolException"><paramref name="sequence"/> contains invalid data.</exception>
    public bool TryParse(ReadOnlySequence<byte> sequence,
        out ProxyProtocolAdvanceTo advanceTo,
        [MaybeNullWhen(returnValue: false)] out ProxyProtocolHeader proxyProtocolHeader)
    {
        bool isNotEmpty = !sequence.IsEmpty;
        var sequenceReader = isNotEmpty ? new SequenceReader<byte>(sequence) : default;

        ProxyProtocolHeader value = null!;
        SequencePosition? examined = null;

        bool success;
        ParserStep step = _step;
        try
        {
            success = step switch
            {
                ParserStep.Done => ThrowAlreadyDone(),
                ParserStep.Invalid => ThrowInvalidProtocol(),
                ParserStep.Initial => isNotEmpty && TryConsumeInitial(ref sequenceReader, ref examined, ref value),
                ParserStep.PreambleV1 => isNotEmpty && TryConsumePreambleV1(ref sequenceReader, ref value),
                ParserStep.AddressFamilyV2 => isNotEmpty && TryConsumeAddressFamilyV2(ref sequenceReader, ref examined, ref value),
                ParserStep.LocalV2 => isNotEmpty && TryConsumeLocalV2(ref sequenceReader, ref value),
                ParserStep.TlvV2 => isNotEmpty && TryConsumeTypeLengthValueV2(ref sequenceReader, ref examined, ref value),
                _ => ThrowUnknownParserStep(step),
            };
        }
        catch
        {
            if (step != ParserStep.Done && step != ParserStep.Invalid)
            {
                _step = ParserStep.Invalid;
            }
            proxyProtocolHeader = null!;
            advanceTo = default;
            throw;
        }

        proxyProtocolHeader = value;
        SequencePosition advanceToConsumed = isNotEmpty ? sequenceReader.Position : sequence.Start;
        SequencePosition advanceToExamined = isNotEmpty ? examined.GetValueOrDefault(advanceToConsumed) : advanceToConsumed;
        advanceTo = new ProxyProtocolAdvanceTo(advanceToConsumed, advanceToExamined);
        return success;
    }

    private unsafe bool TryConsumeInitial(ref SequenceReader<byte> sequenceReader, ref SequencePosition? examined, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        long remainingBytes = sequenceReader.Remaining;
        ParserUtility.Assert(_bytesFilled == 0);
        ParserUtility.Assert(_proxyAddrLength == 0);

        var sig_v1 = ParserConstants.PreambleV1;
        var sig_v2 = ParserConstants.SigV2;

        // verify the preamble / signature
        // but only start parsing when there is enough bytes available
        bool startsWithV1 = ParserUtility.StartsWith(ref sequenceReader, sig_v1);
        bool startsWithV2 = !startsWithV1 && ParserUtility.StartsWith(ref sequenceReader, sig_v2);

        if (startsWithV2 && remainingBytes >= len_v2)
        {
            ParserUtility.Assert(len_v2 > hdr_v2.sig_len);

            sequenceReader.Advance(hdr_v2.sig_len);
            return TryConsumeInitialV2(ref sequenceReader, ref examined, ref proxyProtocolHeader);
        }
        if (startsWithV1 && remainingBytes >= len_v1)
        {
            ParserUtility.Assert(len_v1 > ParserConstants.PreambleV1Length);

            sequenceReader.Advance(ParserConstants.PreambleV1Length);
            var preambleV1 = MemoryMarshal.CreateSpan(ref _raw_hdr.v1.line[0], ParserConstants.PreambleV1Length);
            sig_v1.CopyTo(preambleV1);

            _step = ParserStep.PreambleV1;
            _bytesFilled = ParserConstants.PreambleV1Length;
            return TryConsumePreambleV1(ref sequenceReader, ref proxyProtocolHeader);
        }

        // startsWith will be true if there are no bytes available
        // if no bytes matched with preamble / signature, then protocol message is invalid
        if (!startsWithV1 && !startsWithV2)
        {
            ParserThrowHelper.ThrowInvalidProtocol();
        }

        SequenceReader<byte> copy = sequenceReader;
        copy.AdvanceToEnd();
        examined = copy.Position;
        return false;
    }

    private unsafe bool TryConsumeInitialV2(ref SequenceReader<byte> sequenceReader, ref SequencePosition? examined, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        if (!sequenceReader.TryRead(out byte ver_cmd) || (ver_cmd & 0xF0) != 0x20)
        {
            ParserThrowHelper.ThrowInvalidProtocol();
        }
        _raw_hdr.v2.ver_cmd = ver_cmd;
        if (!sequenceReader.TryRead(out byte fam))
        {
            ParserThrowHelper.ThrowInvalidProtocol();
        }
        _raw_hdr.v2.fam = fam;
        if (!sequenceReader.TryReadBigEndian(out short slen))
        {
            ParserThrowHelper.ThrowInvalidProtocol();
        }
        ushort len = _raw_hdr.v2.len = unchecked((ushort)slen);

        var sig_v2 = MemoryMarshal.CreateSpan(ref _raw_hdr.v2.sig[0], hdr_v2.sig_len);
        ParserConstants.SigV2.CopyTo(sig_v2);

        int cmd = ver_cmd & 0x0F;
        if (cmd == 0x00)
        {
            _step = ParserStep.LocalV2;
            _bytesFilled = len_v2;
            return TryConsumeLocalV2(ref sequenceReader, ref proxyProtocolHeader);
        }
        else if (cmd == 0x01)
        {
            int proxyAddrLength = fam switch
            {
                // AF_UNSPEC
                >= 0x00 and <= 0x02 => 0,
                // TCPv4 / UDPv4
                >= 0x10 and <= 0x12 => sizeof(ip4),
                // TCPv6 / UDPv6
                >= 0x20 and <= 0x22 => sizeof(ip6),
                // UNIX stream / datagram
                >= 0x30 and <= 0x32 => SizeOfUnix(len),
                _ => ThrowProxyV2InvalidFam(fam),
            };

            if (proxyAddrLength > len)
            {
                ParserThrowHelper.ThrowInvalidLength();
            }

            _proxyAddrLength = (byte)proxyAddrLength;
            _step = ParserStep.AddressFamilyV2;
            _bytesFilled = len_v2;
            return TryConsumeAddressFamilyV2(ref sequenceReader, ref examined, ref proxyProtocolHeader);
        }
        ParserThrowHelper.ThrowInvalidProtocol();
        return false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe int SizeOfUnix(ushort len)
    {
        if (len < sizeof(unix))
        {
            ParserThrowHelper.ThrowUnixAddressToShort();
        }
        return sizeof(unix);
    }

    private bool TryConsumeLocalV2(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        int length = _raw_hdr.v2.len + len_v2;
        if (!Discard(ref sequenceReader, length))
        {
            return false;
        }

        proxyProtocolHeader = new ProxyProtocolHeader(
            ProxyVersion.V2,
            ProxyCommand.Local,
            length,
            AddressFamily.Unspecified,
            SocketType.Unknown,
            Source: null,
            Destination: null
        );
        _step = ParserStep.Done;
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int GetActualProxyAddrLength()
    {
        int proxyAddrLength = _proxyAddrLength;
        if (proxyAddrLength == 0)
        {
            proxyAddrLength = _raw_hdr.v2.len;
        }
        return proxyAddrLength;
    }

    private bool TryConsumeAddressFamilyV2(ref SequenceReader<byte> sequenceReader, ref SequencePosition? examined, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        int proxyAddrLength = GetActualProxyAddrLength();

        int length = proxyAddrLength + len_v2;

        byte fam = _raw_hdr.v2.fam;
        if (fam >= 0x00 && fam <= 0x02) // AF_UNSPEC
        {
            if (!Discard(ref sequenceReader, length))
            {
                return false;
            }
        }
        else
        {
            if (!Consume(ref sequenceReader, length, advancePast: true))
            {
                return false;
            }

            int tlvLength = _raw_hdr.v2.len - proxyAddrLength;
            ParserUtility.Assert(tlvLength >= 0, "tlv length is negative");

            if (tlvLength > 0)
            {
                _step = ParserStep.TlvV2;
                return TryConsumeTypeLengthValueV2(ref sequenceReader, ref examined, ref proxyProtocolHeader);
            }
        }

        proxyProtocolHeader = CreateProxyProtocolHeaderV2(length);
        _step = ParserStep.Done;
        return true;
    }

    private unsafe bool TryConsumePreambleV1(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        int crlfOffset = _bytesFilled;
        ParserUtility.Assert(crlfOffset >= 1, "starting offset is too small");

        bool isComplete = Consume(ref sequenceReader, sizeof(hdr_v1), advancePast: false);

        int bytesFilled = _bytesFilled;
        ParserUtility.Assert(bytesFilled >= 0);

        int bytesCopied = bytesFilled - crlfOffset;
        ParserUtility.Assert(bytesCopied >= 0);

        if (bytesCopied > 0)
        {
            ReadOnlySpan<byte> line = MemoryMarshal.CreateReadOnlySpan(ref _raw_hdr.v1.line[0], bytesFilled);

            // search a bit more to the left
            // because "\r" and "\n" could be split between multiple calls
            int crlfIndex = line.Slice(crlfOffset - 1, bytesCopied + 1)
                .IndexOf(ParserConstants.DelimiterV1);

            if (crlfIndex != -1)
            {
                // we just read from crlfOffset to bytesFilled
                // but actually we only need to consume up to "\r\n"
                int lineIndex = crlfOffset - 1 + crlfIndex;

                int lineEnd = lineIndex + ParserConstants.DelimiterV1Length;
                int toAdvance = lineEnd - crlfOffset;
                ParserUtility.Assert(toAdvance >= 0, "attempted to advance backwards");

                sequenceReader.Advance(toAdvance);

                proxyProtocolHeader = ParseSpanV1(line[ParserConstants.PreambleV1Length..lineIndex]);
                _step = ParserStep.Done;
                return true;
            }

            if (isComplete)
            {
                ParserThrowHelper.ThrowMissingCrlf();
            }

            sequenceReader.Advance(bytesCopied);
        }

        return false;
    }

    private unsafe bool TryConsumeTypeLengthValueV2(ref SequenceReader<byte> sequenceReader, ref SequencePosition? examined, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        long remaining = sequenceReader.Remaining;
        if (remaining == 0)
        {
            return false;
        }


        ushort len = _raw_hdr.v2.len;
        int tlvLength = len - GetActualProxyAddrLength();
        ParserUtility.Assert(tlvLength > 0);

        // make sure we can read TLVs all at once
        if (remaining < tlvLength)
        {
            SequenceReader<byte> copy = sequenceReader;
            copy.AdvanceToEnd();
            examined = copy.Position;
            return false;
        }

        int totalLength = _bytesFilled + tlvLength;

        try
        {
            if (BitConverter.IsLittleEndian)
            {
                _raw_hdr.v2.len = BinaryPrimitives.ReverseEndianness(len);
            }

            if (totalLength <= sizeof(hdr))
            {
                proxyProtocolHeader = ConsumeTypeLengthValueFromSpanV2(
                    tlvLength,
                    in sequenceReader,
                    span: MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref _raw_hdr, 1))[..totalLength]
                );
            }
            else if (totalLength <= TLV_STACKALLOC_THRESHOLD)
            {
                Span<byte> scratch = stackalloc byte[totalLength];
                proxyProtocolHeader = ConsumeTypeLengthValueFromSpanV2(
                    tlvLength, in sequenceReader,
                    span: CopyFilledHeaderPart(scratch)
                );
            }
            else
            {
                byte[] array = ArrayPool<byte>.Shared.Rent(totalLength);
                try
                {
                    proxyProtocolHeader = ConsumeTypeLengthValueFromSpanV2(
                        tlvLength,
                        in sequenceReader,
                        span: CopyFilledHeaderPart(array.AsSpan(0, totalLength))
                    );
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(array);
                }
            }
        }
        finally
        {
            if (BitConverter.IsLittleEndian)
            {
                _raw_hdr.v2.len = len;
            }
        }

        sequenceReader.Advance(tlvLength);
        _step = ParserStep.Done;
        return true;
    }

    private Span<byte> CopyFilledHeaderPart(Span<byte> destination)
    {
        MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref _raw_hdr, 1))[.._bytesFilled]
            .CopyTo(destination);
        return destination;
    }

    private unsafe ProxyProtocolHeader ConsumeTypeLengthValueFromSpanV2(int tlvLength, in SequenceReader<byte> sequenceReader, Span<byte> span)
    {
        int totalLength = span.Length;
        ParserUtility.Assert(totalLength > tlvLength);
        int index = totalLength - tlvLength;

        if (!sequenceReader.TryCopyTo(span[index..]))
        {
            ParserThrowHelper.ThrowProxyFailedCopy(tlvLength);
        }

        ReadOnlyCollectionBuilder<ProxyProtocolTlv>? builder = null;
        while (index < totalLength)
        {
            if (totalLength - index < 3)
            {
                ParserThrowHelper.ThrowInvalidLength();
            }
            byte type = span[index];
            int length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(index + 1, 2));
            ParserUtility.Assert(length >= 0);

            int newIndex = index + length + 3;
            if (newIndex > totalLength)
            {
                ParserThrowHelper.ThrowInvalidLength();
            }
            Span<byte> value = span.Slice(index + 3, length);

            var item = BuildTlv(type, value, span);
            if (item is not null)
            {
                (builder ??= new()).Add(item);
            }
            index = newIndex;
        }

        if (index != totalLength)
        {
            ParserThrowHelper.ThrowInvalidLength();
        }

        var result = CreateProxyProtocolHeaderV2(
            totalLength,
            builder?.Count > 0 ? builder.ToReadOnlyCollection() : null
        );
        return result;
    }

    private ProxyProtocolTlv? BuildTlv(byte type, Span<byte> value, Span<byte> span)
    {
        var ptype = (ProxyProtocolTlvType)type;
        return ptype switch
        {
            PP2_TYPE_NOOP => null,

            PP2_TYPE_ALPN => value.IsEmpty ? ThrowProxyV2AlpnEmpty() : new ProxyProtocolTlvAlpn(value.ToArray()),
            PP2_TYPE_AUTHORITY => ParserUtility.ParseAuthority(value),
            PP2_TYPE_CRC32C => ValidateCrc32C(value, span),
            PP2_TYPE_UNIQUE_ID => ParserUtility.ParseUniqueId(value),
            PP2_TYPE_SSL => ParserUtility.ParseSslTlv(value),
            PP2_TYPE_NETNS => ParserUtility.ParseNetNamespace(value),

            >= PP2_TYPE_MIN_CUSTOM and <= PP2_TYPE_MAX_CUSTOM => new ProxyProtocolTlvCustom(ptype, value.ToArray()),
            >= PP2_TYPE_MIN_EXPERIMENT and <= PP2_TYPE_MAX_EXPERIMENT => new ProxyProtocolTlvExperiment(ptype, value.ToArray()),

            >= PP2_SUBTYPE_SSL_VERSION and <= PP2_SUBTYPE_SSL_KEY_ALG => ThrowProxyV2InvalidTlvType(type, "reserved for SSL sub TLV subtypes"),
            >= PP2_TYPE_MIN_FUTURE and <= PP2_TYPE_MAX_FUTURE => ThrowProxyV2InvalidTlvType(type, "reserved for future"),
            _ => ThrowProxyV2InvalidTlvType(type, "unrecognized type"),
        };
    }

    private unsafe ProxyProtocolTlv? ValidateCrc32C(Span<byte> value, Span<byte> span)
    {
        const int HashLengthBytes = Crc32C.Hasher.SizeBits / 8;

        if (value.Length != HashLengthBytes)
        {
            ParserThrowHelper.ThrowInvalidLength();
        }
        Span<byte> copy = stackalloc byte[HashLengthBytes];
        value.CopyTo(copy);
        value.Clear();

        try
        {
            uint actual = Crc32C.Hasher.ComputeHash(span);
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(copy);
            if (actual != expected)
            {
                ParserThrowHelper.ThrowInvalidChecksum();
            }
            return new ProxyProtocolTlvCRC32C(actual);
        }
        finally
        {
            copy.CopyTo(value);
        }
    }

    private ProxyProtocolHeader CreateProxyProtocolHeaderV2(int length, IReadOnlyList<ProxyProtocolTlv>? typeLengthValues = null)
    {
        byte fam = _raw_hdr.v2.fam;

        return fam switch
        {
            0x00 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Unknown, typeLengthValues: typeLengthValues),
            0x10 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Unknown, MapIPv4(), typeLengthValues: typeLengthValues),
            0x20 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Unknown, MapIPv6(), typeLengthValues: typeLengthValues),
            0x30 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Unknown, MapUnix(), typeLengthValues: typeLengthValues),

            0x01 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Stream, typeLengthValues: typeLengthValues),
            0x11 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Stream, MapIPv4(), typeLengthValues: typeLengthValues),
            0x21 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Stream, MapIPv6(), typeLengthValues: typeLengthValues),
            0x31 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Stream, MapUnix(), typeLengthValues: typeLengthValues),

            0x02 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Dgram, typeLengthValues: typeLengthValues),
            0x12 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Dgram, MapIPv4(), typeLengthValues: typeLengthValues),
            0x22 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Dgram, MapIPv6(), typeLengthValues: typeLengthValues),
            0x32 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Dgram, MapUnix(), typeLengthValues: typeLengthValues),
            _ => ThrowProxyV2InvalidSocketTypeFam(fam),
        };
    }

    private static ProxyProtocolHeader CreateProxyProtocolHeaderV2(int length, AddressFamily addressFamily, SocketType socketType,
       (EndPoint? source, EndPoint? destination) endpoints = default,
       IReadOnlyList<ProxyProtocolTlv>? typeLengthValues = null
    )
    {
        return new(ProxyVersion.V2, ProxyCommand.Proxy, length,
            addressFamily, socketType, endpoints.source, endpoints.destination,
            typeLengthValues
        );
    }

    private static ProxyProtocolHeader ParseSpanV1(ReadOnlySpan<byte> line)
    {
        int length = line.Length + ParserConstants.PreambleV1Length + ParserConstants.DelimiterV1Length;

        const byte sep = (byte)' ';
        if (!ParserUtility.TrySplit(ref line, sep, out ReadOnlySpan<byte> segment) || !segment.IsEmpty)
        {
            ParserThrowHelper.ThrowMissingProxySpaceV1("PROXY");
        }

        bool hasNext = ParserUtility.TrySplit(ref line, sep, out segment);
        bool isIPv6 = false;

        if (!hasNext)
        {
            // shorthand with "PROXY UNKNOWN\r\n"
            if (!line.StartsWith(ParserConstants.ProtocolUnknown) || !segment.IsEmpty)
            {
                ParserThrowHelper.ThrowMissingProxySpaceV1("TCP4/TCP6");
            }
            return GetUnknownV1Header(length);
        }
        else if (segment.SequenceEqual(ParserConstants.ProtocolTCP4))
        {
            isIPv6 = false;
        }
        else if (segment.SequenceEqual(ParserConstants.ProtocolTCP6))
        {
            isIPv6 = true;
        }
        else if (segment.SequenceEqual(ParserConstants.ProtocolUnknown))
        {
            return GetUnknownV1Header(length);
        }
        else
        {
            ParserThrowHelper.ThrowInvalidProtocolNameV1();
        }

        if (!ParserUtility.TrySplit(ref line, sep, out segment))
        {
            ParserThrowHelper.ThrowMissingProxySpaceV1("source address");
        }

        var srcAddress = ParserUtility.ParseIPAddress(isIPv6, segment, "src_addr");
        if (!ParserUtility.TrySplit(ref line, sep, out segment))
        {
            ParserThrowHelper.ThrowMissingProxySpaceV1("destination address");
        }

        var dstAddress = ParserUtility.ParseIPAddress(isIPv6, segment, "dst_addr");
        if (!ParserUtility.TrySplit(ref line, sep, out segment))
        {
            ParserThrowHelper.ThrowMissingProxySpaceV1("source port");
        }
        var srcPort = ParserUtility.ParsePortNumber(segment, "src_port");
        if (ParserUtility.TrySplit(ref line, sep, out segment) || !segment.IsEmpty)
        {
            ParserThrowHelper.ThrowBogusV1();
        }
        ushort dstPort = ParserUtility.ParsePortNumber(line, "dst_port");

        return new ProxyProtocolHeader(
            ProxyVersion.V1,
            ProxyCommand.Proxy,
            length,
            isIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,
            SocketType.Stream,
            Source: new IPEndPoint(srcAddress, srcPort),
            Destination: new IPEndPoint(dstAddress, dstPort)
        );
    }

    private static ProxyProtocolHeader GetUnknownV1Header(int length)
    {
        return new ProxyProtocolHeader(
               ProxyVersion.V1,
               ProxyCommand.Proxy,
               length,
               AddressFamily.Unspecified,
               SocketType.Unknown,
               Source: null,
               Destination: null
        );
    }

    /// <summary>
    /// Resets the parser to initial state.
    /// </summary>
    public void Reset()
    {
        this = default;
    }

    private (EndPoint? source, EndPoint? destination) MapIPv4()
    {
        ref ip4 ip4 = ref _raw_hdr.v2.proxy_addr.ip4;
        var src = ParserUtility.CreateIPAddress(ip4.src_addr, nameof(ip4.src_addr));
        var dst = ParserUtility.CreateIPAddress(ip4.dst_addr, nameof(ip4.dst_addr));

        var source = ParserUtility.CreateEndpointFromAddressAndPortUInt16BigEndian(src, ip4.src_port);
        var destination = ParserUtility.CreateEndpointFromAddressAndPortUInt16BigEndian(dst, ip4.dst_port);

        return (source, destination);
    }

    private unsafe (EndPoint? source, EndPoint? destination) MapIPv6()
    {
        ref ip6 ip6 = ref _raw_hdr.v2.proxy_addr.ip6;

        var src_addr = MemoryMarshal.CreateReadOnlySpan(ref ip6.src_addr[0], ip6.addr_len);
        var src = ParserUtility.CreateIPAddress(src_addr, nameof(src_addr));

        var dst_addr = MemoryMarshal.CreateReadOnlySpan(ref ip6.dst_addr[0], ip6.addr_len);
        var dst = ParserUtility.CreateIPAddress(dst_addr, nameof(dst_addr));

        var source = ParserUtility.CreateEndpointFromAddressAndPortUInt16BigEndian(src, ip6.src_port);
        var destination = ParserUtility.CreateEndpointFromAddressAndPortUInt16BigEndian(dst, ip6.dst_port);

        return (source, destination);
    }

    private unsafe (EndPoint? source, EndPoint? destination) MapUnix()
    {
        ref hdr_v2 v2 = ref _raw_hdr.v2;
        ref unix unix = ref v2.proxy_addr.unix;

        var src_addr = MemoryMarshal.CreateReadOnlySpan(ref unix.src_addr[0], unix.addr_len);
        var source = ParserUtility.CreateUnixEndPoint(src_addr, nameof(src_addr));
        var dst_addr = MemoryMarshal.CreateReadOnlySpan(ref unix.dst_addr[0], unix.addr_len);
        var destination = ParserUtility.CreateUnixEndPoint(dst_addr, nameof(dst_addr));

        return (source, destination);
    }

    private bool Discard(ref SequenceReader<byte> sequenceReader, int length)
    {
        ParserUtility.Assert(length >= 0);

        int bytesFilled = _bytesFilled;
        ParserUtility.Assert(bytesFilled >= 0);

        int bytesToFill = length - bytesFilled;
        ParserUtility.Assert(bytesToFill >= 0);

        if (bytesToFill == 0)
        {
            return true;
        }

        long remainingBytes = sequenceReader.Remaining;

        bool success;
        if (bytesToFill <= remainingBytes)
        {
            success = true;
        }
        else
        {
            bytesToFill = (int)remainingBytes;
            success = false;
        }

        _bytesFilled = bytesFilled + bytesToFill;
        sequenceReader.Advance(bytesToFill);

        return success;
    }

    private bool Consume(ref SequenceReader<byte> sequenceReader, int length, bool advancePast)
    {
        ParserUtility.Assert(length >= 0);

        int bytesFilled = _bytesFilled;
        ParserUtility.Assert(bytesFilled >= 0);

        int bytesToFill = length - bytesFilled;
        ParserUtility.Assert(bytesToFill >= 0);

        if (bytesToFill == 0)
        {
            return true;
        }

        long remainingBytes = sequenceReader.Remaining;

        bool success;
        if (bytesToFill <= remainingBytes)
        {
            success = true;
        }
        else
        {
            bytesToFill = (int)remainingBytes;
            success = false;
        }

        Span<byte> raw_bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref _raw_hdr, 1));
        if (!sequenceReader.TryCopyTo(raw_bytes.Slice(bytesFilled, bytesToFill)))
        {
            ParserThrowHelper.ThrowProxyFailedCopy(bytesToFill);
        }

        _bytesFilled = bytesFilled + bytesToFill;
        if (advancePast)
        {
            sequenceReader.Advance(bytesToFill);
        }

        return success;
    }

    [DoesNotReturn]
    private static bool ThrowAlreadyDone()
    {
        ParserThrowHelper.ThrowAlreadyDone();
        return false;
    }

    [DoesNotReturn]
    private static bool ThrowInvalidProtocol()
    {
        ParserThrowHelper.ThrowInvalidProtocol();
        return false;
    }

    [DoesNotReturn]
    private static bool ThrowUnknownParserStep(ParserStep parserStep)
    {
        ParserThrowHelper.ThrowUnknownParserStep(parserStep);
        return false;
    }

    [DoesNotReturn]
    private static ushort ThrowProxyV2InvalidFam(byte fam)
    {
        ParserThrowHelper.ThrowProxyV2InvalidFam(fam);
        return 0;
    }

    [DoesNotReturn]
    private static ProxyProtocolTlv? ThrowProxyV2InvalidTlvType(byte type, string why)
    {
        ParserThrowHelper.ThrowProxyV2InvalidTlvType(type, why);
        return null;
    }

    [DoesNotReturn]
    private static ProxyProtocolTlv? ThrowProxyV2AlpnEmpty()
    {
        ParserThrowHelper.ThrowZeroByteAlpn();
        return null;
    }

    [DoesNotReturn]
    private static ProxyProtocolHeader ThrowProxyV2InvalidSocketTypeFam(byte fam)
    {
        ParserThrowHelper.ThrowProxyV2InvalidSocketTypeFam(fam);
        return null!;
    }
}