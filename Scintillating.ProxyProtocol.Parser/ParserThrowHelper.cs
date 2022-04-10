using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Scintillating.ProxyProtocol.Parser;

internal static class ParserThrowHelper
{
    [DoesNotReturn]
    private static void _(IFormatProvider? provider,
       [InterpolatedStringHandlerArgument("provider")] ref DefaultInterpolatedStringHandler handler)
    {
        string messsage = string.Create(provider, ref handler);
        throw new ProxyProtocolException(messsage);
    }

    [DoesNotReturn]
    private static void _(IFormatProvider? provider, Span<char> initialBuffer,
       [InterpolatedStringHandlerArgument("provider", "initialBuffer")] ref DefaultInterpolatedStringHandler handler)
    {
        string messsage = string.Create(provider, initialBuffer, ref handler);
        throw new ProxyProtocolException(messsage);
    }

    [DoesNotReturn]
    public static void ThrowInvalidProtocol()
        => throw new ProxyProtocolException("PROXY V1/V2: Invalid protocol header.");

    [DoesNotReturn]
    public static void ThrowBogusV1()
        => throw new ProxyProtocolException("PROXY V1: Bogus protocol message.");

    [DoesNotReturn]
    public static void ThrowInvalidProtocolNameV1()
        => throw new ProxyProtocolException("PROXY V1: Invalid protocol name.");

    [DoesNotReturn]
    public static void ThrowMissingProxySpaceV1(string command)
       => throw new ProxyProtocolException("PROXY V1: Missing space after " + command + " command.");

    [DoesNotReturn]
    public static void ThrowUnixAddressToShort()
     => throw new ProxyProtocolException("PROXY V2: Unix protocol addresses block is too short.");

    [DoesNotReturn]
    public static void ThrowAlreadyDone()
        => throw new ProxyProtocolException("PROXY V1/V2: Parsing is already finished, parser requires reset befor reuse.");

    [DoesNotReturn]
    public static void ThrowMissingCrlf()
       => throw new ProxyProtocolException("PROXY V1: Missing CRLF terminator.");

    [DoesNotReturn]
    public static void ThrowNotImplemented(string message)
        => throw new NotImplementedException(message);

    [DoesNotReturn]
    public static void ThrowInvalidLength()
        => throw new ProxyProtocolException("PROXY V2: Invalid length header.");

    [DoesNotReturn]
    public static void ThrowInvalidUniqueId()
      => throw new ProxyProtocolException("PROXY V2: Unique ID is too big.");

    [DoesNotReturn]
    public static void ThrowZeroByteAlpn()
        => throw new ProxyProtocolException("PROXY V2: ALPN should be a non-empty byte string.");

    [DoesNotReturn]
    public static void ThrowUnixEndpointEmpty(string what)
       => throw new ProxyProtocolException("PROXY V2: UNIX endpoint " + what + " is empty");

    [DoesNotReturn]
    public static void ThrowCantParsePort(string what)
        => throw new ProxyProtocolException("PROXY V1: Can't parse port number " + what + ".");

    [DoesNotReturn]
    public static void ThrowCantParseIPAddress(char r, string what)
        => _(CultureInfo.InvariantCulture, stackalloc char[100], $"PROXY V1: Can't parse IPv{r} address {what}.");

    [DoesNotReturn]
    public static void ThrowProxyV2InvalidSocketTypeFam(byte fam)
        => _(CultureInfo.InvariantCulture, stackalloc char[100], $"PROXY V2: Invalid address/socket type family: 0x{fam:x2}.");

    [DoesNotReturn]
    public static void ThrowProxyV2InvalidFam(byte fam)
        => _(CultureInfo.InvariantCulture, stackalloc char[64], $"PROXY V2: invalid fam value 0x{fam:x2}.");

    [DoesNotReturn]
    public static void ThrowProxyV2InvalidTlvType(byte type, string why)
      => _(CultureInfo.InvariantCulture, stackalloc char[64], $"PROXY V2: invalid tlv type 0x{type:x2}: {why}.");


    [DoesNotReturn]
    public static void ThrowProxyV1FailedCopy(int amountToCopy)
        => _(CultureInfo.InvariantCulture, stackalloc char[100], $"PROXY V1: failed to copy expected amount of bytes ({amountToCopy}).");

    [DoesNotReturn]
    public static void ThrowProxyFailedCopy(int bytes)
     => _(CultureInfo.InvariantCulture, stackalloc char[100], $"PROXY: failed to copy expected amount of bytes ({bytes}).");

    [DoesNotReturn]
    public static void ThrowUnknownParserStep(ParserStep parserStep)
        => _(CultureInfo.InvariantCulture, stackalloc char[128], $"PROXY V1/V2: Unknown {nameof(ParserStep)} value in {nameof(parserStep)}: {parserStep}.");
}