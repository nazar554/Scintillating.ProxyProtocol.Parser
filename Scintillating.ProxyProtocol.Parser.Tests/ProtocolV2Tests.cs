using FluentAssertions;
using System.Buffers;
using System.Net.Sockets;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV2Tests
{
    private ProxyProtocolParser _parser;

    [Theory]
    [MemberData(nameof(GetRealTestCases))]
    public void ShouldWorkWithRealTestCases(byte[] data, ProxyProtocolHeader expected)
    {
        var sequence = new ReadOnlySequence<byte>(data);

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid")
            .Subject;

        success.Should().BeTrue("input data is complete");

        proxyProtocolHeader.Version.Should().Be(expected.Version, "version should match");
        proxyProtocolHeader.Command.Should().Be(expected.Command, "version should match");

        long offset;
        if (expected.Length != 0)
        {
            offset = expected.Length;
            proxyProtocolHeader.Length.Should().Be(expected.Length, "length should match");
        }
        else
        {
            offset = proxyProtocolHeader.Length;
            proxyProtocolHeader.Length.Should().BeGreaterThanOrEqualTo(ProxyProtocolParser.len_v2, "it should be longer than V2 preamble");
        }

        sequence.GetOffset(advanceTo.Consumed).Should().Be(offset, "input data is complete");
        sequence.GetOffset(advanceTo.Examined).Should().Be(offset, "input data is complete");

        proxyProtocolHeader.AddressFamily.Should().Be(expected.AddressFamily, "address family should match");
        proxyProtocolHeader.SocketType.Should().Be(expected.SocketType, "socket type should match");

        if (expected.AddressFamily == AddressFamily.Unix)
        {
            var src = proxyProtocolHeader!.Source.Should().BeOfType<UnixDomainSocketEndPoint>().Subject;
            src.ToString()
                .Should().Be(expected.Source?.ToString(), "source endpoint and port should match");

            var dst = proxyProtocolHeader!.Destination.Should().BeOfType<UnixDomainSocketEndPoint>().Subject;
            dst.ToString()
                .Should().Be(expected.Destination?.ToString(), "source endpoint and port should match");
        }
        else
        {
            proxyProtocolHeader!.Source
                .Should().Be(expected.Source, "source endpoint and port should match");
            proxyProtocolHeader!.Destination
                .Should().Be(expected.Destination, "destination endpoint and port should match");
        }
    }

    private static IEnumerable<object[]> GetRealTestCases()
    {
        yield return new object[]
        {
            new byte[] {
                 0x0d, 0x0a,
                 0x0d, 0x0a,
                 0x00, 0x0d, 0x0a,
                 0x51, 0x55, 0x49, 0x54, 0x0a,
                 0x20, 0x00, 0x00, 0x0f, 0x03, 0x00, 0x04, 0x88, 0x9d, 0xa1, 0xdf, 0x20, 0x00, 0x05, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e,
                 0x30, 0x0d, 0x0a,
                 0x0d, 0x0a,
                 0x53, 0x4d, 0x0d, 0x0a,
                 0x0d, 0x0a,
                 0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
            },
            new ProxyProtocolHeader(
                ProxyVersion.V2,
                ProxyCommand.Local,
                Length: 31,
                AddressFamily.Unspecified,
                SocketType.Unknown,
                Source: null,
                Destination: null
            )
        };
    }
}