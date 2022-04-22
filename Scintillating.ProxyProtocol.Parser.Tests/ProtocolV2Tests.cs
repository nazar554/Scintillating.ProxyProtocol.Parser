using FluentAssertions;
using System.Buffers;
using System.Net;
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
        yield return new object[]
        {
            new byte[] {
                 0x0d, 0x0a                                                                                     // ..
               , 0x0d, 0x0a                                                                                     // ..
               , 0x00, 0x0d, 0x0a                                                                               // ...
               , 0x51, 0x55, 0x49, 0x54, 0x0a                                                                   // QUIT.
               , 0x21, 0x21, 0x00, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff // !!..............
               , 0x0a                                                                                           // .
               , 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a // ................
               , 0x00, 0x00, 0x08, 0x15, 0xbf, 0x01, 0xbb, 0x04, 0x00, 0x04, 0x1d, 0xb8, 0x97, 0x5f, 0x01, 0x00 // ............._..
               , 0x02, 0x68, 0x32, 0x02, 0x00, 0x18, 0x68, 0x61, 0x70, 0x72, 0x6F, 0x78, 0x79, 0x2E, 0x74, 0x65 // .h2...haproxy.te
               , 0x73, 0x74, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x20, 0x00 // st.example.com .
               , 0x58, 0x07, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x07, 0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33 // X.....!..TLSv1.3
               , 0x22, 0x00, 0x16, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x65, 0x78 // "..chost.test.ex
               , 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x25, 0x00, 0x07, 0x52, 0x53, 0x41, 0x32 // ample.com%..RSA2
               , 0x30, 0x34, 0x38, 0x24, 0x00, 0x0a                                                             // 048$..
               , 0x52, 0x53, 0x41, 0x2d, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x23, 0x00, 0x16, 0x54, 0x4c, 0x53 // RSA-SHA256#..TLS
               , 0x5f, 0x41, 0x45, 0x53, 0x5f, 0x32, 0x35, 0x36, 0x5f, 0x47, 0x43, 0x4d, 0x5f, 0x53, 0x48, 0x41 // _AES_256_GCM_SHA
               , 0x33, 0x38, 0x34,                                                                              // 384
            },
            new ProxyProtocolHeader(
                ProxyVersion.V2,
                ProxyCommand.Proxy,
                Length: 0xa6 + ProxyProtocolParser.len_v2,
                AddressFamily.InterNetworkV6,
                SocketType.Stream,
                Source: IPEndPoint.Parse("[::ffff:10.0.0.3]:5567"),
                Destination: IPEndPoint.Parse("[::ffff:10.0.0.8]:443")
            )
        };
    }
}