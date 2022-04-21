using Scintillating.ProxyProtocol.Parser.Tlv;
using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;

namespace Scintillating.ProxyProtocol.Parser;

internal static class ParserUtility
{
    private static readonly UTF8Encoding _encoding = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly Encoding _asciiEncoding = Encoding.GetEncoding(Encoding.ASCII.WebName, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);

    [Conditional("DEBUG")]
    public static void Assert(bool condition, 
        string? detailMessage = null, 
        [CallerArgumentExpression(parameterName: "condition")] string? message = null,
        [CallerFilePath]string? filePath = null,
        [CallerLineNumber] int lineNumber = default,
        [CallerMemberName] string? memberName = null
    )
    {
        Debug.Assert(condition, $"{message} at {memberName} ({filePath}:{lineNumber})", detailMessage);
    }

    public static ProxyProtocolTlv ParseAuthority(Span<byte> value)
    {
        Assert(value.Length >= 0);
        int length = value.Length;
        if (length == 0)
        {
            throw new ProxyProtocolException("PROXY V2: Authority should be a non-empty string.");
        }
        else if (length >= ProxyProtocolTlvAuthority.MaxLength)
        {
            throw new ProxyProtocolException("PROXY V2: authority TLV is too long.");
        }

        string authority;
        try
        {
            authority = _encoding.GetString(value);
        }
        catch (ArgumentException ex)
        {
            throw new ProxyProtocolException("PROXY V2: invalid UTF-8 bytes in authority TLV.", ex);
        }

        return new ProxyProtocolTlvAuthority(authority, value.Length);
    }

    public static ProxyProtocolTlv ParseSslTlv(Span<byte> value)
    {
        _ = value;
        throw new ProxyProtocolException("PROXY V2: parsing SSL TLV's is not yet implemented.");
    }

    public static ProxyProtocolTlv ParseNetNamespace(Span<byte> value)
    {
        Assert(value.Length >= 0);
        if (value.IsEmpty)
        {
            return new ProxyProtocolTlvNetNamespace(string.Empty);
        }

        string @namespace;
        try
        {
            @namespace = _asciiEncoding.GetString(value);
        }
        catch (ArgumentException ex)
        {
            throw new ProxyProtocolException("PROXY V2: invalid US-ASCII bytes in namespace TLV.", ex);
        }

        return new ProxyProtocolTlvNetNamespace(@namespace);
    }

    public static ProxyProtocolTlv ParseUniqueId(Span<byte> value)
    {
        if (value.Length >= ProxyProtocolTlvUniqueID.MaxLength)
        {
            ParserThrowHelper.ThrowInvalidUniqueId();
        }

        return new ProxyProtocolTlvUniqueID(value.ToArray());
    }

    public static bool TryParsePortNumber(ReadOnlySpan<byte> source, out ushort port)
    {
        bool success = Utf8Parser.TryParse(source, out ushort value, out int length, 'd')
            && length == source.Length;

        port = success ? value : default;
        return success;
    }

    public static bool StartsWith(ref SequenceReader<byte> sequenceReader, ReadOnlySpan<byte> span, bool advancePast = false)
    {
        long bytesRemaining = sequenceReader.Remaining;
        if (bytesRemaining < span.Length)
        {
            int length = (int)bytesRemaining;
            span = span[..length];
        }
        return sequenceReader.IsNext(span, advancePast);
    }

    public static bool TrySplit(ref ReadOnlySpan<byte> source, byte sep, out ReadOnlySpan<byte> segment)
    {
        int index = source.IndexOf(sep);
        if (index == -1)
        {
            segment = default;
            return false;
        }

        segment = source[..index];
        int next = index + 1;
        source = next < source.Length ? source[next..] : default;
        return true;
    }

    public static ushort ParsePortNumber(ReadOnlySpan<byte> source, string what)
    {
        if (!TryParsePortNumber(source, out var port))
        {
            ParserThrowHelper.ThrowCantParsePort(what);
        }
        return port;
    }

    public static IPAddress ParseIPAddress(bool isIPv6, ReadOnlySpan<byte> source, string what)
    {
        if (!TryParseIPAddress(source, out var ipAddress, isIPv6))
        {
            ParserThrowHelper.ThrowCantParseIPAddress(isIPv6 ? '6' : '4', what);
        }
        return ipAddress;
    }

    public static IPAddress CreateIPAddress(ReadOnlySpan<byte> address, string what)
    {
        try
        {
            return new IPAddress(address);
        }
        catch (ArgumentException ex)
        {
            throw new ProxyProtocolException("PROXY V2: failed to create IP address " + what + ".", ex);
        }
    }

    public static IPAddress CreateIPAddress(long address, string what)
    {
        try
        {
            return new IPAddress(address);
        }
        catch (ArgumentException ex)
        {
            throw new ProxyProtocolException("PROXY V2: failed to parse IP address " + what + ".", ex);
        }
    }

    public static IPEndPoint CreateEndpointFromAddressAndPortUInt16BigEndian(IPAddress address, ushort port_be)
    {
        ushort port = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(port_be) : port_be;

        return new IPEndPoint(address, port);
    }

    public static UnixDomainSocketEndPoint CreateUnixEndPoint(ReadOnlySpan<byte> source, string what)
    {
        if (source.IsEmpty)
        {
            ParserThrowHelper.ThrowUnixEndpointEmpty(what);
        }

        int offset = 0;
        if (source[0] == (byte)'\0')
        {
            offset = 1;
        }
        int zero = source[offset..].IndexOf((byte)'\0');
        if (zero != -1)
        {
            source = source[..(offset + zero)];
        }

        string path;
        try
        {
            path = _encoding.GetString(source);
        }
        catch (ArgumentException ex)
        {
            throw new ProxyProtocolException("PROXY V2: invalid UTF-8 bytes in " + what + ".", ex);
        }

        try
        {
            return new UnixDomainSocketEndPoint(path);
        }
        catch (Exception ex)
        {
            throw new ProxyProtocolException("PROXY V2: failed to create UNIX socket endpoint " + what + ".", ex);
        }
    }

    public static bool TryParseIPAddress(ReadOnlySpan<byte> source, [MaybeNullWhen(returnValue: false)] out IPAddress ipAddress, bool isIPv6 = false)
    {
        ipAddress = null!;

        // :: or 1.1.1.1
        int minLength = isIPv6 ? 2 : 7;

        // 0000:0000:0000:0000:0000:ffff:192.168.100.228 or 192.168.100.228
        int maxLength = isIPv6 ? 45 : 15;

        int length = source.Length;
        if (length < minLength || length > maxLength)
        {
            return false;
        }

        Span<char> chars = stackalloc char[length];
        if (Encoding.ASCII.GetChars(source, chars) != length)
        {
            return false;
        }

        if (!IPAddress.TryParse(chars, out var value))
        {
            return false;
        }

        AddressFamily addressFamily = isIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        if (value.AddressFamily != addressFamily)
        {
            return false;
        }

        ipAddress = value;
        return true;
    }
}