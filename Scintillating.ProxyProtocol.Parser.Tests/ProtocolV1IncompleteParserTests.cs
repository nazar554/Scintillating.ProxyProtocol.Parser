using FluentAssertions;
using FluentAssertions.Execution;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV1IncompleteParserTests
{
    private ProxyProtocolParser _parser;

    [Fact]
    public void ShouldIgnoreIncompleteV1Data()
    {
        var sequence = "PROXY ".AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid, but incomplete").Subject;
        success.Should().BeFalse("input data is incomplete");
        proxyProtocolHeader.Should().BeNull();

        sequence.GetOffset(advanceTo.Consumed).Should().Be(0, "input data is incomplete");
        sequence.GetOffset(advanceTo.Examined).Should().Be(sequence.Length, "input data is complete");
    }

    [Fact]
    public void ShouldThrowOnInvalidIncompleteV1Data()
    {
        var sequence = "IND? ".AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        func.Should().ThrowExactly<ProxyProtocolException>("input data is invalid");
        proxyProtocolHeader.Should().BeNull();
        advanceTo.Consumed.Should().Be(default(SequencePosition));
        advanceTo.Examined.Should().Be(default(SequencePosition));
    }

    [Theory]
    [MemberData(nameof(GetIncompleteChunks))]
    public void ShouldParseByChunks(string?[] chunks,
        AddressFamily addressFamily, SocketType socketType,
        IPEndPoint? source = null, IPEndPoint? destination = null
    )
    {
        int expectedLength = 0;
        bool end = false;
        int lastChunk = chunks.Length - 1;
        var sequenceChunks = new ReadOnlySequence<byte>[chunks.Length];
        for (int index = 0; index < chunks.Length; ++index)
        {
            string? chunk = chunks[index];
            // marker for end of data
            if (chunk is null)
            {
                // previous chunk is the last expected one
                lastChunk = index - 1;
                end = true;
            }
            else
            {
                var sequence = chunk.AsReadOnlyByteSequence();
                sequenceChunks[index] = sequence;
                if (!end)
                {
                    expectedLength += chunk.Length;
                }
            }
        }

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;

        int consumed = 0;
        for (int index = 0; index < sequenceChunks.Length; ++index)
        {
            var sequence = sequenceChunks[index];
            var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

            if (index <= lastChunk)
            {
                bool success = func.Should().NotThrow("it's valid data").Subject;
                if (index < lastChunk)
                {
                    success.Should().BeFalse("it's not a final chunk");
                    proxyProtocolHeader.Should().BeNull("it's not a final chunk");

                    sequence.GetOffset(advanceTo.Examined)
                        .Should().Be(sequence.Length, "all data of a partial chunk must be examined");

                    if (consumed == 0 && sequence.Length < ProxyProtocolParser.len_v1)
                    {
                        sequence.GetOffset(advanceTo.Consumed)
                            .Should().Be(0, "initial chunk is not long enough to be consumed");

                        string chunk = chunks[index]!;
                        string next = chunks[index + 1] = chunk + chunks[index + 1];
                        sequenceChunks[index + 1] = next.AsReadOnlyByteSequence();
                    }
                    else
                    {
                        consumed++;
                        sequence.GetOffset(advanceTo.Consumed)
                            .Should().Be(sequence.Length, "all data of a partial chunk must be consumed");
                    }
                }
                else
                {
                    consumed++;
                    success.Should().BeTrue("it's the final chunk");
                    proxyProtocolHeader.Should().NotBeNull("it's the final chunk");

                    string chunk = chunks[index]!;
                    string prev = index > 0 ? chunks[index - 1]! : string.Empty;
                    string complete = prev + chunk;

                    const string crlf = "\r\n";
                    int crlfIndex = complete.IndexOf(crlf, StringComparison.Ordinal);
                    crlfIndex.Should().NotBe(-1, "last chunk's test data should contain CRLF");

                    int offset = crlfIndex + crlf.Length - prev.Length;

                    sequence.GetOffset(advanceTo.Consumed)
                       .Should().BeGreaterThanOrEqualTo(offset, "everything up to CRLF and after must be examined");

                    sequence.GetOffset(advanceTo.Examined)
                        .Should().BeGreaterThanOrEqualTo(offset, "everything up to CRLF and after must be examined");
                    using (new AssertionScope(nameof(proxyProtocolHeader)))
                    {
                        proxyProtocolHeader!.Version
                            .Should().Be(ProxyVersion.V1, "testing human-readable protocol");
                        proxyProtocolHeader!.Command
                            .Should().Be(ProxyCommand.Proxy, "there is a single command in protocol V1");
                        proxyProtocolHeader!.Length
                            .Should().Be(expectedLength, "entire header has to be consumed");

                        proxyProtocolHeader!.AddressFamily
                            .Should().Be(addressFamily, "it should match the sample");
                        proxyProtocolHeader!.SocketType
                            .Should().Be(socketType, "it should match the sample");

                        proxyProtocolHeader!.Source
                            .Should().Be(source, "source endpoint and port should match");
                        proxyProtocolHeader!.Destination
                            .Should().Be(destination, "destination endpoint and port should match");
                    }
                }
            }
            else
            {
                // extra data after last chunk
                func.Should().ThrowExactly<ProxyProtocolException>("parsing is done");
                proxyProtocolHeader.Should().BeNull("parsing is done");
                advanceTo.Should().Be(default(ProxyProtocolAdvanceTo), "parsing is done");
            }
        }
    }

    public static IEnumerable<object[]> GetIncompleteChunks()
    {
        yield return new object[] {
            new string[] { "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n" },
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("255.255.255.255:65535"),
            IPEndPoint.Parse("255.255.255.255:65535"),
        };
        yield return new object[] {
            new string[] { "PROXY TCP4 255.255.255.255" , " 255.255.255.255 65535 65535\r\n" },
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("255.255.255.255:65535"),
            IPEndPoint.Parse("255.255.255.255:65535"),
        };
        yield return new object[] {
            new string[] { "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ff", "ff:ffff:ffff ffff:ffff:ffff:ffff:ffff:f", "fff:ffff:ffff 65534 65535\r\n" },
            AddressFamily.InterNetworkV6,
            SocketType.Stream,
            IPEndPoint.Parse("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65534"),
            IPEndPoint.Parse("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
        };
        yield return new object[] {
            new string?[] {
                "PR", "OXY TCP4 255.", "255.255.255 255.", "255.255", ".255 655", "", "35 65535\r", "\n",
                null, "GET /", "HTTP1/.0\r\n"
            },
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("255.255.255.255:65535"),
            IPEndPoint.Parse("255.255.255.255:65535"),
        };
        yield return new object[] {
            new string?[] {
                "PR", "OXY TCP4 255.", "255.255.255 255.", "255.255", ".255 655", "", "35 65535\r", "\n",
                null, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            },
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("255.255.255.255:65535"),
            IPEndPoint.Parse("255.255.255.255:65535"),
        };
    }
}