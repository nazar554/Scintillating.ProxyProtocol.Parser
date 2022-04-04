using Xunit;
using FluentAssertions;
using System.Net.Sockets;
using System.Net;
using FluentAssertions.Execution;
using System.Buffers;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV1CompleteValidDataParserTests
{
    private ProxyProtocolParser _parser;

    [Theory]
    [MemberData(nameof(GetCompleteValidData))]
    public void ShouldWorkWithCompleteValidData(string line,
        AddressFamily addressFamily, SocketType socketType,
        IPEndPoint? source = null, IPEndPoint? destination = null
    )
    {
        ReadOnlySequence<byte> sequence = line.AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid")
            .Subject;

        success.Should().BeTrue("input data is complete");

        sequence.GetOffset(advanceTo.Consumed).Should().Be(sequence.Length, "input data is complete");
        sequence.GetOffset(advanceTo.Examined).Should().Be(sequence.Length, "input data is complete");
        
        using (new AssertionScope(nameof(proxyProtocolHeader)))
        {
            proxyProtocolHeader
                .Should().NotBeNull("input data is complete");

            proxyProtocolHeader!.Version
                .Should().Be(ProxyVersion.V1, "testing human-readable protocol");
            proxyProtocolHeader!.Command
                .Should().Be(ProxyCommand.Proxy, "there is a single command in protocol V1");
            proxyProtocolHeader!.Length
                .Should().Be((ushort)sequence.Length, "entire header has to be consumed");

            proxyProtocolHeader!.AddressFamily
                .Should().Be(addressFamily, "example uses TCP4");
            proxyProtocolHeader!.SocketType
                .Should().Be(socketType, "example uses TCP4");

            proxyProtocolHeader!.Source
                .Should().Be(source, "source endpoint and port should match");
            proxyProtocolHeader!.Destination
                .Should().Be(destination, "destination endpoint and port should match");
        }
    }

    private static IEnumerable<object[]> GetCompleteValidData()
    {
        yield return new object[] {
            "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("255.255.255.255:65535"),
            IPEndPoint.Parse("255.255.255.255:65535"),
        };
        yield return new object[] {
            "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n",
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("192.168.0.1:56324"),
            IPEndPoint.Parse("192.168.0.11:443"),
        };
        yield return new object[] {
            "PROXY TCP6 ffff::1 ffff::2 65534 65535\r\n",
            AddressFamily.InterNetworkV6,
            SocketType.Stream,
            IPEndPoint.Parse("[ffff::1]:65534"),
            IPEndPoint.Parse("[ffff::2]:65535"),
        };
        yield return new object[] {
            "PROXY UNKNOWN\r\n",
            AddressFamily.Unspecified,
            SocketType.Unknown,
        };
        yield return new object[] {
            "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n",
            AddressFamily.Unspecified,
            SocketType.Unknown,
        };
        yield return new object[]
        {
            "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65534 65535\r\n",
            AddressFamily.InterNetworkV6,
            SocketType.Stream,
            IPEndPoint.Parse("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65534"),
            IPEndPoint.Parse("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
        };
    }
}
