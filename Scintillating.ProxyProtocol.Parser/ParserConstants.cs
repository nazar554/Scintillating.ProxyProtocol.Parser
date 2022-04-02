namespace Scintillating.ProxyProtocol.Parser;

internal static class ParserConstants
{
    public const int PreambleV1Length = 5;

    public static ReadOnlySpan<byte> PreambleV1 => new byte[] { (byte)'P', (byte)'R', (byte)'O', (byte)'X', (byte)'Y' };

    public static ReadOnlySpan<byte> SigV2 => new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

    public static ReadOnlySpan<byte> DelimiterV1 => new byte[] { (byte)'\r', (byte)'\n' };

    public static ReadOnlySpan<byte> Space => new byte[] { (byte)' ' };


    public const int DelimiterV1Length = 2;

    public static ReadOnlyMemory<byte> Http2Id { get; } = new byte[] { 0x68, 0x32 };

    public static ReadOnlyMemory<byte> Http11Id { get; } = new byte[] { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 };

    // HTTP2 Connection preface starts with the string "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    public static ReadOnlySpan<byte> PrefaceHTTP2 => new byte[] { 0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a };

    public const int PrefaceHTTP2Length = 24;

    public static ReadOnlySpan<byte> ProtocolUnknown => new byte[] { (byte)'U', (byte)'N', (byte)'K', (byte)'N', (byte)'O', (byte)'W', (byte)'N' };

    public static ReadOnlySpan<byte> ProtocolTCP4 => new byte[] { (byte)'T', (byte)'C', (byte)'P', (byte)'4' };

    public static ReadOnlySpan<byte> ProtocolTCP6 => new byte[] { (byte)'T', (byte)'C', (byte)'P', (byte)'6' };
}