﻿using FluentAssertions;
using Scintillating.ProxyProtocol.Parser.Util;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

    [Theory]
    [InlineData(0xf408c634b3a9142UL, 0x2ce33edeu)]
    [InlineData(0x80539e8c7c352e2bUL, 0xc49cc573u)]
    [InlineData(0x62e9121db6e4d649UL, 0xb8683c96u)]
    [InlineData(0x899345850ed0a286UL, 0x6918660du)]
    [InlineData(0x2302df11b4a43b15UL, 0xa904e522u)]
    [InlineData(0xe943de7b3d35d70UL, 0x52dbc42cu)]
    [InlineData(0xdf1ff2bf41abf56bUL, 0x98863c22u)]
    [InlineData(0x9bc138abae315de2UL, 0x894d5d2cu)]
    [InlineData(0x31cc82e56234f0ffUL, 0xb003745du)]
    [InlineData(0xce63c0cd6988e847UL, 0xfc496dbdu)]
    [InlineData(0x3e42f6b78ee352faUL, 0x97d2fbb5u)]
    [InlineData(0xfa4085436078cfa6UL, 0x3c062ef1u)]
    [InlineData(0x53349558bf670a4bUL, 0xcc2eff18u)]
    [InlineData(0x2714e10e7d722c61UL, 0x6a9b09f6u)]
    [InlineData(0xc0d3261addfc6908UL, 0x420242c1u)]
    [InlineData(0xd1567c3181d3a1bfUL, 0xfd562dc3u)]
    public void ShouldWorkBasicCorrectness(ulong input, uint expectedReflectedHash)
    {
        Func<uint> action = () =>
        {
            Span<byte> buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(buffer, input);
            var hasher = new Crc32C.Hasher();
            hasher.HashCore(buffer);
            return hasher.HashValue;
        };
        var actual = action.Should().NotThrow().Subject;
        actual.Should().Be(expectedReflectedHash);
    }
}