using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Scintillating.ProxyProtocol.Parser;

internal static class ParserUtility
{
    private static readonly UTF8Encoding _encoding = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool TryParsePortNumber(ReadOnlySpan<byte> source, out ushort port)
    {
        bool success = Utf8Parser.TryParse(source, out ushort value, out int length, 'd')
            && length == source.Length;

        port = success ? value : default;
        return success;
    }

    public static bool StartsWith(ref SequenceReader<byte> sequenceReader, ReadOnlySpan<byte> span, bool advancePast = false)
    {
        if (sequenceReader.Remaining < span.Length)
        {
            int length = (int)sequenceReader.Remaining;
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