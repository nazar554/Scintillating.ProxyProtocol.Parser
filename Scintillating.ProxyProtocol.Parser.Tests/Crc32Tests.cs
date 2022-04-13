using FluentAssertions;
using Scintillating.ProxyProtocol.Parser.Util;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class Crc32Tests
{
    private readonly Crc32C _crc32c = new();

    [Theory]
    [MemberData(nameof(RfcExamples))]
    public void ShouldWorkWithRfcExamples(byte[] payload, byte[] expected)
    {
        Func<byte[]> action = () => _crc32c.ComputeHash(payload);
        var actual = action.Should().NotThrow().Subject;
        actual.Should().Equal(expected);
    }

    public static IEnumerable<object[]> RfcExamples()
    {
        yield return new[]
        {
            new byte[32],
            new byte[]{ 0xaa, 0x36, 0x91, 0x8a },
        };
        yield return new[]
        {
            new byte[7],
            new byte[]{ 0x6D, 0x6A, 0x3E, 0xBB },
        };
        yield return new[]
        {
            new byte[3],
            new byte[]{ 0x7A, 0xA3, 0x64, 0x60 },
        };
        yield return new[]
        {
            new byte[1],
            new byte[]{ 0x51, 0x53, 0x7D, 0x52 },
        };
        yield return new[]
        {
            Array.Empty<byte>(),
            new byte[4],
        };
        yield return new[]
        {
            Enumerable.Repeat((byte)0xFF, 32).ToArray(),
            new byte[]{ 0x43, 0xab, 0xa8, 0x62 },
        };
        yield return new[]
        {
            Enumerable.Range(0, 0x1F + 1).Select(x => (byte)x).ToArray(),
            new byte[]{ 0x4e, 0x79, 0xdd, 0x46 },
        };
        yield return new[]
        {
            Enumerable.Range(0, 0x1F + 1).Select(x => (byte)(0x1F - x)).ToArray(),
            new byte[]{ 0x5c, 0xdb, 0x3f, 0x11 },
        };
        yield return new[]
        {
            new byte[]
            {
                0x01, 0xc0, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x14, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x14,
                0x00, 0x00, 0x00, 0x18,
                0x28, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            },
            new byte[] { 0x56, 0x3a, 0x96, 0xd9 }
        };
    }
}