using FluentAssertions;
using FluentAssertions.Execution;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests;


public class ProtocolV2IncompleteParserTests
{
    private ProxyProtocolParser _parser;

    [Fact]
    public void ShouldIgnoreIncompleteV2Data()
    {
        var sequence = new ReadOnlySequence<byte>(
            new byte[] { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51 }
        );

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
    public void ShouldThrowOnInvalidIncompleteV2Data()
    {
        var sequence = new ReadOnlySequence<byte>(
            new byte[] { 0x0d, 0x0a, 0xdc, 0x0a }
        );

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
    public void ShouldParseByChunks(byte[]?[] chunks,
        int expectedLength,
        ProxyCommand command,
        AddressFamily addressFamily, SocketType socketType,
        IPEndPoint? source = null, IPEndPoint? destination = null
    )
    {
        int lastChunk = chunks.Length - 1;
        var sequenceChunks = new ReadOnlySequence<byte>[chunks.Length];
        for (int index = 0; index < chunks.Length; ++index)
        {
            byte[]? chunk = chunks[index];
            // marker for end of data
            if (chunk is null)
            {
                // previous chunk is the last expected one
                lastChunk = index - 1;
            }
            else
            {
                var sequence = new ReadOnlySequence<byte>(chunk);
                sequenceChunks[index] = sequence;
            }
        }

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;

        long totalConsumed = 0;
        int chunksConsumed = 0;
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

                    if (chunksConsumed == 0 && sequence.Length < ProxyProtocolParser.len_v2)
                    {
                        sequence.GetOffset(advanceTo.Consumed)
                            .Should().Be(0, "initial chunk is not long enough to be consumed");

                        byte[] chunk = chunks[index]!;
                        byte[] next = chunks[index + 1] = chunk.Concat(chunks[index + 1]!).ToArray();
                        sequenceChunks[index + 1] = new ReadOnlySequence<byte>(next);
                    }
                    else
                    {
                        totalConsumed += sequence.Length;
                        chunksConsumed++;
                        sequence.GetOffset(advanceTo.Consumed)
                            .Should().Be(sequence.Length, "all data of a partial chunk must be consumed");
                    }
                }
                else
                {
                    chunksConsumed++;

                    success.Should().BeTrue("it's the final chunk");
                    proxyProtocolHeader.Should().NotBeNull("it's the final chunk");

                    long offset = expectedLength - totalConsumed;

                    sequence.GetOffset(advanceTo.Consumed)
                       .Should().BeGreaterThanOrEqualTo(offset, "everything must be consumed");

                    sequence.GetOffset(advanceTo.Examined)
                        .Should().BeGreaterThanOrEqualTo(offset, "everything must be examined");
                    using (new AssertionScope(nameof(proxyProtocolHeader)))
                    {
                        proxyProtocolHeader!.Version
                            .Should().Be(ProxyVersion.V2, "testing binary protocol");
                        proxyProtocolHeader!.Command
                            .Should().Be(command, "command should match");
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
            new byte[]?[] {
                new byte[] {
                    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                    0x21,
                    0x11,
                    0x00, 0x0c,
                    0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x2A, 0x05, 0x39
                },
                null,
            },
            28,
            ProxyCommand.Proxy,
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("127.0.0.1:42"),
            IPEndPoint.Parse("127.0.0.1:1337"),
        };
        yield return new object[] {
            new byte[]?[] {
                Array.Empty<byte>(),
                new byte[] {
                    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                    0x21,
                    0x11,
                    0x00, 0x0c,
                },
                new byte[] { 0x7F, 0x00, 0x00, 0x01, },
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                new byte[] { 0x7F, 0x00, 0x00, 0x01, 0x00, 0x2A, 0x05, 0x39, 0xFF, 0x00, 0xFF },
                null,
            },
            28,
            ProxyCommand.Proxy,
            AddressFamily.InterNetwork,
            SocketType.Stream,
            IPEndPoint.Parse("127.0.0.1:42"),
            IPEndPoint.Parse("127.0.0.1:1337"),
        };
        yield return new object[] {
            new byte[]?[] {
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
                null,
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.InterNetworkV6,
            SocketType.Dgram,
            IPEndPoint.Parse("[::1]:42"),
            IPEndPoint.Parse("[::1]:1337"),
        };
        yield return new object[] {
            new byte[]?[] {
                new byte[] { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a } ,
                Array.Empty<byte>(),
                new byte[] {
                    0x51, 0x55, 0x49, 0x54, 0x0a,
                    0x21,
                    0x22,
                    0x00, 0x24,
                },
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, },
                new byte[] {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    0x00, 42,
                    0b00000101, 0b00111001,
                    0xFF, 0x00, 0xFF
                },
                null,
            },
            52,
            ProxyCommand.Proxy,
            AddressFamily.InterNetworkV6,
            SocketType.Dgram,
            IPEndPoint.Parse("[::1]:42"),
            IPEndPoint.Parse("[::1]:1337"),
        };
    }
}