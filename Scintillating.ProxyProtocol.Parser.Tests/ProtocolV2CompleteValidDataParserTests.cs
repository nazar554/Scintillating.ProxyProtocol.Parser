using FluentAssertions;
using FluentAssertions.Execution;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV2CompleteValidDataParserTests
{
    private ProxyProtocolParser _parser;

    [Theory]
    [MemberData(nameof(GetCompleteValidData))]
    public void ShouldWorkWithCompleteValidData(byte[] data,
        long? length,
        ProxyCommand command,
        AddressFamily addressFamily, SocketType socketType,
        EndPoint? source = null, EndPoint? destination = null
    )
    {
        var sequence = new ReadOnlySequence<byte>(data);

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid")
            .Subject;

        success.Should().BeTrue("input data is complete");

        long offset = length ?? data.Length;

        sequence.GetOffset(advanceTo.Consumed).Should().Be(offset, "input data is complete");
        sequence.GetOffset(advanceTo.Examined).Should().Be(offset, "input data is complete");

        using (new AssertionScope(nameof(proxyProtocolHeader)))
        {
            proxyProtocolHeader
                .Should().NotBeNull("input data is complete");

            proxyProtocolHeader!.Version
                .Should().Be(ProxyVersion.V2, "testing binary protocol");
            proxyProtocolHeader!.Command
                .Should().Be(command, "command should be valid");
            proxyProtocolHeader!.Length
                .Should().Be((ushort)offset, "entire header has to be consumed");

            proxyProtocolHeader!.AddressFamily
                .Should().Be(addressFamily, "it should match the sample");
            proxyProtocolHeader!.SocketType
                .Should().Be(socketType, "it should match the sample");

            if (addressFamily == AddressFamily.Unix)
            {
                var src = proxyProtocolHeader!.Source.Should().BeOfType<UnixDomainSocketEndPoint>().Subject;
                src.ToString()
                    .Should().Be(source?.ToString(), "source endpoint and port should match");

                var dst = proxyProtocolHeader!.Destination.Should().BeOfType<UnixDomainSocketEndPoint>().Subject;
                dst.ToString()
                    .Should().Be(destination?.ToString(), "source endpoint and port should match");
            }
            else
            {
                proxyProtocolHeader!.Source
                    .Should().Be(source, "source endpoint and port should match");
                proxyProtocolHeader!.Destination
                    .Should().Be(destination, "destination endpoint and port should match");
            }
        }
    }

    private static byte[] Unix(string path)
    {
        return Encoding.UTF8.GetBytes(path.PadRight(108, '\0'));
    }

    private static IEnumerable<object?[]> GetCompleteValidData()
    {
        yield return new object?[] {
            new byte[] { 
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x11,
                0x00, 0x0c,
                0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x2A, 0x05, 0x39
            },
            null,
            ProxyCommand.Proxy,
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("127.0.0.1:42"),
            IPEndPoint.Parse("127.0.0.1:1337"),
        };
        yield return new object?[] {
            new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x11,
                0x00, 0x0c,
                0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x2A, 0x05, 0x39,
                0xFF, 0x00, 0xFF
            },
            28,
            ProxyCommand.Proxy,
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("127.0.0.1:42"),
            IPEndPoint.Parse("127.0.0.1:1337"),
        };
        yield return new object?[] {
            new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x22,
                0x00, 0x24,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 42,
                0b00000101, 0b00111001,
                0xFF, 0x00, 0xFF
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.InterNetworkV6,
            SocketType.Dgram,
            IPEndPoint.Parse("[::1]:42"),
            IPEndPoint.Parse("[::1]:1337"),
        };
        yield return new object?[] {
                new byte[] {
                    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                    0x21,
                    0x31,
                    0x00, 0xD8,
                }
                .Concat(Unix("\0test"))
                .Concat(Unix("/a dummy path\0extra"))
                .Concat(new byte[] { 0xFF, 0x00, 0xFC })
                .ToArray(),
            232,
            ProxyCommand.Proxy,
            AddressFamily.Unix,
            SocketType.Stream,
            new UnixDomainSocketEndPoint("\0test"),
            new UnixDomainSocketEndPoint("/a dummy path"),
        };
        yield return new object?[] {
            new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x20,
                0x00, 0x24,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 35,
                0b00000101, 0b00111001,
                0xFF, 0x00, 0xFF
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.InterNetworkV6,
            SocketType.Unknown,
            IPEndPoint.Parse("[::1]:35"),
            IPEndPoint.Parse("[::1]:1337"),
        };
        yield return new object?[] {
            new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x00,
                0x00, 0x24,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 35,
                0b00000101, 0b00111001,
                0xFF, 0x00, 0xFF
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.Unspecified,
            SocketType.Unknown,
            null
        };
        yield return new object?[] {
            new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21,
                0x01,
                0x00, 0x24,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 35,
                0b00000101, 0b00111001,
                0xFF, 0x00, 0xFF
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.Unspecified,
            SocketType.Stream,
            null
        };
    }
}