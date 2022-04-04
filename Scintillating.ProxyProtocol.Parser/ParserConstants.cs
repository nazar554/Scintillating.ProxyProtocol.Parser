namespace Scintillating.ProxyProtocol.Parser;

internal static class ParserConstants
{
    public const int PreambleV1Length = 5;

    public static ReadOnlySpan<byte> PreambleV1 => new byte[] { (byte)'P', (byte)'R', (byte)'O', (byte)'X', (byte)'Y' };

    public static ReadOnlySpan<byte> SigV2 => new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

    public static ReadOnlySpan<byte> DelimiterV1 => new byte[] { (byte)'\r', (byte)'\n' };

    public const int DelimiterV1Length = 2;

    public static ReadOnlySpan<byte> ProtocolUnknown => new byte[] { (byte)'U', (byte)'N', (byte)'K', (byte)'N', (byte)'O', (byte)'W', (byte)'N' };

    public static ReadOnlySpan<byte> ProtocolTCP4 => new byte[] { (byte)'T', (byte)'C', (byte)'P', (byte)'4' };

    public static ReadOnlySpan<byte> ProtocolTCP6 => new byte[] { (byte)'T', (byte)'C', (byte)'P', (byte)'6' };
}