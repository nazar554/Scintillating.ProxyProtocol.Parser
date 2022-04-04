﻿using Scintillating.ProxyProtocol.Parser.raw;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[module: SkipLocalsInit]

namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// PROXY Protocol header parser, supports partial headers, is re-usable.
/// </summary>
[StructLayout(LayoutKind.Auto)]
public struct ProxyProtocolParser
{
    internal const AddressFamily AF_UNSPEC = AddressFamily.Unspecified;

    // sizeof(raw.hdr_v2.sig) + sizeof(ver_cmd) + sizeof(fam) + sizeof(len) = 16
    internal const int len_v2 = hdr_v2.sig_len + sizeof(byte) + sizeof(byte) + sizeof(short);

    // "PROXY \r\n".Length = sizeof("PROXY") + sizeof((byte)' ') + sizeof("\r\n") = 8
    internal const int len_v1 = ParserConstants.PreambleV1Length + ParserConstants.DelimiterV1Length + sizeof(byte);

    private ushort _v2HeaderLengthWithoutTlv;
    private ushort _bytesFilled;
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
        var sequenceReader = new SequenceReader<byte>(sequence);
        ProxyProtocolHeader value = null!;

        SequencePosition? examined = null;
        bool success;
        ParserStep step = _step;
        try
        {
            success = step switch
            {
                ParserStep.Initial => TryConsumeInitial(ref sequenceReader, ref examined, ref value),
                ParserStep.PreambleV1 => TryConsumePreambleV1(ref sequenceReader, ref value),
                ParserStep.AddressFamilyV2 => TryConsumeAddressFamilyV2(ref sequenceReader, ref value),
                ParserStep.LocalV2 => TryConsumeLocalV2(ref sequenceReader, ref value),
                ParserStep.TypeLengthValueV2 => TryConsumeTypeLengthValueV2(ref sequenceReader, ref value),
                ParserStep.Done => ThrowAlreadyDone(),
                ParserStep.Invalid => ThrowInvalidProtocol(),
                _ => ThrowUnknownParserStep(step),
            };
        }
        catch when (step != ParserStep.Done && step != ParserStep.Invalid)
        {
            _step = ParserStep.Invalid;
            throw;
        }

        proxyProtocolHeader = value;
        var consumed = sequenceReader.Position;
        advanceTo = new ProxyProtocolAdvanceTo(consumed, examined ?? consumed);
        return success;
    }

    private unsafe bool TryConsumeInitial(ref SequenceReader<byte> sequenceReader, ref SequencePosition? examined, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        long remainingBytes = sequenceReader.Remaining;
        Debug.Assert(remainingBytes >= 0, nameof(remainingBytes) + " is negative.");
        Debug.Assert(_bytesFilled == 0, nameof(_bytesFilled) + " is non zero.");
        Debug.Assert(_v2HeaderLengthWithoutTlv == 0, nameof(_v2HeaderLengthWithoutTlv) + " is non zero.");

        bool isEnoughBytesRemainingForV2 = remainingBytes >= len_v2;

        var signature = ParserConstants.SigV2;
        if (isEnoughBytesRemainingForV2 && sequenceReader.IsNext(signature, advancePast: true))
        {
            return TryConsumeInitialV2(ref sequenceReader, ref proxyProtocolHeader);
        }

        if (remainingBytes >= len_v1)
        {
            var preambleV1 = ParserConstants.PreambleV1;
            if (sequenceReader.IsNext(preambleV1, advancePast: true))
            {
                var sig_v1 = MemoryMarshal.CreateSpan(ref _raw_hdr.v1.line[0], ParserConstants.PreambleV1Length);
                preambleV1.CopyTo(sig_v1);

                _bytesFilled = ParserConstants.PreambleV1Length;

                _step = ParserStep.PreambleV1;
                return TryConsumePreambleV1(ref sequenceReader, ref proxyProtocolHeader);
            }

            if (isEnoughBytesRemainingForV2 || !ParserUtility.StartsWith(ref sequenceReader, signature))
            {
                ParserThrowHelper.ThrowInvalidProtocol();
            }
        }

        SequenceReader<byte> copy = sequenceReader;
        copy.AdvanceToEnd();
        examined = copy.Position;
        return false;
    }

    private unsafe bool TryConsumeInitialV2(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
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

        _bytesFilled = len_v2;

        int cmd = ver_cmd & 0x0F;
        if (cmd == 0x00)
        {
            _v2HeaderLengthWithoutTlv = (ushort)(len + len_v2);
            _step = ParserStep.LocalV2;
            return TryConsumeLocalV2(ref sequenceReader, ref proxyProtocolHeader);
        }
        else if (cmd == 0x01)
        {
            ushort proxyAddrLength = fam switch
            {
                // AF_UNSPEC
                >= 0x00 and <= 0x02 => len,
                // TCPv4 / UDPv4
                >= 0x10 and <= 0x12 => ip4.size,
                // TCPv6 / UDPv6
                >= 0x20 and <= 0x22 => ip6.size,
                // UNIX stream / datagram
                >= 0x30 and <= 0x32 => unix.size,
                _ => ThrowProxyV2InvalidFam(fam),
            };
            if (len < proxyAddrLength)
            {
                ParserThrowHelper.ThrowInvalidLength();
            }

            _v2HeaderLengthWithoutTlv = (ushort)(proxyAddrLength + len_v2);
            _step = ParserStep.AddressFamilyV2;
            return TryConsumeAddressFamilyV2(ref sequenceReader, ref proxyProtocolHeader);
        }
        ParserThrowHelper.ThrowInvalidProtocol();
        return false;
    }

    private bool TryConsumeLocalV2(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        ushort length = _v2HeaderLengthWithoutTlv;
        if (!Discard(ref sequenceReader, length))
        {
            return false;
        }

        proxyProtocolHeader = new ProxyProtocolHeader(
            ProxyVersion.V1,
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

    private bool TryConsumeAddressFamilyV2(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        int length = _v2HeaderLengthWithoutTlv;
        if (!Consume(ref sequenceReader, length, advancePast: true))
        {
            return false;
        }

        int tlvLength = _raw_hdr.v2.len - length;
        Debug.Assert(tlvLength >= 0, nameof(tlvLength) + " is negative.");

        if (tlvLength > 0)
        {
            _step = ParserStep.TypeLengthValueV2;
            return TryConsumeTypeLengthValueV2(ref sequenceReader, ref proxyProtocolHeader);
        }

        proxyProtocolHeader = CreateProxyProtocolHeaderV2();
        _step = ParserStep.Done;
        return true;
    }

    private unsafe bool TryConsumePreambleV1(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        int crlfOffset = _bytesFilled;
        Debug.Assert(crlfOffset >= 0, nameof(crlfOffset) + " is negative.");

        bool isComplete = Consume(ref sequenceReader, hdr_v1.size, advancePast: false);

        int bytesFilled = _bytesFilled;
        Debug.Assert(bytesFilled >= 0, nameof(bytesFilled) + " is negative.");

        Span<byte> line = MemoryMarshal.CreateSpan(ref _raw_hdr.v1.line[0], bytesFilled);
        int crlfLength = bytesFilled - crlfOffset;
        Debug.Assert(crlfLength >= 0, nameof(crlfLength) + " is negative.");

        int crlfIndex = line.Slice(crlfOffset, crlfLength)
            .IndexOf(ParserConstants.DelimiterV1);

        if (crlfIndex != -1)
        {
            int lineIndex = crlfOffset + crlfIndex;
            if (lineIndex > bytesFilled)
            {
                int count = lineIndex - bytesFilled + ParserConstants.DelimiterV1Length;
                if (count > 0)
                {
                    sequenceReader.Advance(count);
                }
            }
            proxyProtocolHeader = ParseSpanV1(line[ParserConstants.PreambleV1Length..lineIndex]);
            _step = ParserStep.Done;
            return true;
        }

        if (isComplete)
        {
            ParserThrowHelper.ThrowMissingCrlf();
        }

        sequenceReader.Advance(crlfLength);
        return false;
    }

    private static unsafe bool TryConsumeTypeLengthValueV2(ref SequenceReader<byte> sequenceReader, ref ProxyProtocolHeader proxyProtocolHeader)
    {
        ParserThrowHelper.ThrowNotImplemented("PROXY V2: Reading TLVs not yet implemented.");
        _ = sequenceReader;
        _ = proxyProtocolHeader;
        return false;
    }

    private ProxyProtocolHeader CreateProxyProtocolHeaderV2()
    {
        ref hdr_v2 v2 = ref _raw_hdr.v2;
        ref proxy_addr addr = ref v2.proxy_addr;
        byte fam = v2.fam;
        ushort len = v2.len;
        var length = (ushort)(len + len_v2);

        return fam switch
        {
            0x00 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Unknown),
            0x10 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Unknown, MapIPv4(ref addr.ip4)),
            0x20 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Unknown, MapIPv6(ref addr.ip6)),
            0x30 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Unknown, MapUnix(len, ref addr.unix)),

            0x01 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Stream),
            0x11 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Stream, MapIPv4(ref addr.ip4)),
            0x21 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Stream, MapIPv6(ref addr.ip6)),
            0x31 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Stream, MapUnix(len, ref addr.unix)),

            0x02 => CreateProxyProtocolHeaderV2(length, AF_UNSPEC, SocketType.Dgram),
            0x12 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetwork, SocketType.Dgram, MapIPv4(ref addr.ip4)),
            0x22 => CreateProxyProtocolHeaderV2(length, AddressFamily.InterNetworkV6, SocketType.Dgram, MapIPv6(ref addr.ip6)),
            0x32 => CreateProxyProtocolHeaderV2(length, AddressFamily.Unix, SocketType.Dgram, MapUnix(len, ref addr.unix)),
            _ => ThrowProxyV2InvalidSocketTypeFam(fam),
        };
    }

    private ProxyProtocolHeader CreateProxyProtocolHeaderV2(
       ushort length, AddressFamily addressFamily, SocketType socketType,
       (EndPoint? source, EndPoint? destination) endpoints = default
    )
    {
        return new(ProxyVersion.V2, ProxyCommand.Proxy, length,
            addressFamily, socketType, endpoints.source, endpoints.destination
        );
    }

    private static ProxyProtocolHeader ParseSpanV1(ReadOnlySpan<byte> line)
    {
        var length = (ushort)(line.Length + ParserConstants.PreambleV1Length + ParserConstants.DelimiterV1Length);

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

    private static ProxyProtocolHeader GetUnknownV1Header(ushort length)
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

    private static (EndPoint? source, EndPoint? destination) MapIPv4(ref ip4 ip4)
    {
        var src = ParserUtility.CreateIPAddress(ip4.src_addr, nameof(ip4.src_addr));
        var dst = ParserUtility.CreateIPAddress(ip4.dst_addr, nameof(ip4.dst_addr));

        var source = new IPEndPoint(src, ip4.src_port);
        var destination = new IPEndPoint(dst, ip4.dst_port);

        return (source, destination);
    }

    private static unsafe (EndPoint? source, EndPoint? destination) MapIPv6(ref ip6 ip6)
    {
        var src_addr = MemoryMarshal.CreateReadOnlySpan(ref ip6.src_addr[0], ip6.addr_len);
        var src = ParserUtility.CreateIPAddress(src_addr, nameof(src_addr));

        var dst_addr = MemoryMarshal.CreateReadOnlySpan(ref ip6.dst_addr[0], ip6.addr_len);
        var dst = ParserUtility.CreateIPAddress(dst_addr, nameof(dst_addr));

        var source = new IPEndPoint(src, ip6.src_port);
        var destination = new IPEndPoint(dst, ip6.dst_port);

        return (source, destination);
    }

    private static unsafe (EndPoint? source, EndPoint? destination) MapUnix(ushort len, ref unix unix)
    {
        if (len < unix.size)
        {
            ParserThrowHelper.ThrowUnixAddressToShort();
        }

        var src_addr = MemoryMarshal.CreateReadOnlySpan(ref unix.src_addr[0], unix.addr_len);
        var source = ParserUtility.CreateUnixEndPoint(src_addr, nameof(src_addr));
        var dst_addr = MemoryMarshal.CreateReadOnlySpan(ref unix.dst_addr[0], unix.addr_len);
        var destination = ParserUtility.CreateUnixEndPoint(dst_addr, nameof(dst_addr));

        return (source, destination);
    }

    private bool Discard(ref SequenceReader<byte> sequenceReader, int length)
    {
        int bytesFilled = _bytesFilled;
        Debug.Assert(bytesFilled >= 0, nameof(bytesFilled) + " is negative.");

        int bytesToFill = length - bytesFilled;
        Debug.Assert(bytesToFill >= 0, nameof(bytesToFill) + " is negative.");

        if (bytesToFill == 0)
        {
            return true;
        }

        long remainingBytes = sequenceReader.Remaining;
        Debug.Assert(remainingBytes >= 0, nameof(remainingBytes) + " is negative.");

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

        _bytesFilled = (ushort)(bytesFilled + bytesToFill);
        sequenceReader.Advance(bytesToFill);

        return success;
    }

    private bool Consume(ref SequenceReader<byte> sequenceReader, int length, bool advancePast)
    {
        int bytesFilled = _bytesFilled;
        Debug.Assert(bytesFilled >= 0, nameof(bytesFilled) + " is negative.");

        int bytesToFill = length - bytesFilled;
        Debug.Assert(bytesToFill >= 0, nameof(bytesToFill) + " is negative.");

        if (bytesToFill == 0)
        {
            return true;
        }

        long remainingBytes = sequenceReader.Remaining;
        Debug.Assert(remainingBytes >= 0, nameof(remainingBytes) + " is negative.");

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

        _bytesFilled = (ushort)(bytesFilled + bytesToFill);
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
    private static ProxyProtocolHeader ThrowProxyV2InvalidSocketTypeFam(byte fam)
    {
        ParserThrowHelper.ThrowProxyV2InvalidSocketTypeFam(fam);
        return null!;
    }
}