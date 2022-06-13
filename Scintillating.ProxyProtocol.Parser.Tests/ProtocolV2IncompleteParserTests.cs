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

    private static IEnumerable<object[]> GetIncompleteChunks()
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

        yield return new object[] {
            new byte[]?[] {
                new byte[] { /* Packet 4 */
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
                0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x11,
                0x2e, 0x76, 0x78, 0xd1, 0x6d, 0x69, 0xd8, 0x8e,
                0x7d, 0x21, 0x01, 0xbb, 0x01, 0x00, 0x02, 0x68,
                0x32 },
                null,
                new byte[] { /* Packet 6 */
                0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
                0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
                0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
                0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00,
                0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xef, 0x00, 0x01 },
                new byte[] { /* Packet 8 */
                0x00, 0x01, 0xde, 0x01, 0x25, 0x00, 0x00, 0x00,
                0x01, 0x80, 0x00, 0x00, 0x00, 0xff, 0x82, 0x41,
                0x96, 0x40, 0xec, 0x90, 0x76, 0xf5, 0x1d, 0x8b,
                0x48, 0x17, 0x0a, 0x52, 0x3a, 0xf0, 0x63, 0x68,
                0x2b, 0xcb, 0x47, 0xa5, 0xe4, 0x2f, 0x7f, 0x87,
                0x04, 0x86, 0x61, 0x1e, 0x07, 0x34, 0xc5, 0xb3,
                0x58, 0x87, 0xa4, 0x7e, 0x56, 0x1c, 0xc5, 0x80,
                0x1f, 0x40, 0x87, 0x41, 0x48, 0xb1, 0x27, 0x5a,
                0xd1, 0xff, 0xb8, 0xfe, 0x54, 0xd2, 0x74, 0xa9,
                0x0f, 0xdd, 0xdb, 0x07, 0x54, 0x9f, 0xcf, 0xdf,
                0x78, 0x3f, 0x97, 0xdf, 0xfe, 0x7e, 0x94, 0xfe,
                0x6f, 0x4f, 0x61, 0xe9, 0x35, 0xb4, 0xff, 0x3f,
                0x7d, 0xe0, 0xfe, 0x42, 0x00, 0xff, 0x3f, 0x4a,
                0x7f, 0x38, 0x8e, 0x79, 0xa8, 0x2a, 0x97, 0xa7,
                0xb0, 0xf4, 0x97, 0xf9, 0xfb, 0xef, 0x07, 0xf2,
                0x10, 0x07, 0xf9, 0x40, 0x8b, 0x41, 0x48, 0xb1,
                0x27, 0x5a, 0xd1, 0xad, 0x49, 0xe3, 0x35, 0x05,
                0x02, 0x3f, 0x30, 0x40, 0x8d, 0x41, 0x48, 0xb1,
                0x27, 0x5a, 0xd1, 0xad, 0x5d, 0x03, 0x4c, 0xa7,
                0xb2, 0x9f, 0x88, 0xfe, 0x79, 0x1a, 0xa9, 0x0f,
                0xe1, 0x1f, 0xcf, 0x40, 0x03, 0x64, 0x6e, 0x74,
                0x01, 0x31, 0x40, 0x92, 0xb6, 0xb9, 0xac, 0x1c,
                0x85, 0x58, 0xd5, 0x20, 0xa4, 0xb6, 0xc2, 0xad,
                0x61, 0x7b, 0x5a, 0x54, 0x25, 0x1f, 0x01, 0x31,
                0x7a, 0xd8, 0xd0, 0x7f, 0x66, 0xa2, 0x81, 0xb0,
                0xda, 0xe0, 0x53, 0xfa, 0xe4, 0x6a, 0xa4, 0x3f,
                0x84, 0x29, 0xa7, 0x7a, 0x81, 0x02, 0xe0, 0xfb,
                0x53, 0x91, 0xaa, 0x71, 0xaf, 0xb5, 0x3c, 0xb8,
                0xd7, 0xf6, 0xa4, 0x35, 0xd7, 0x41, 0x79, 0x16,
                0x3c, 0xc6, 0x4b, 0x0d, 0xb2, 0xea, 0xec, 0xb8,
                0xa7, 0xf5, 0x9b, 0x1e, 0xfd, 0x19, 0xfe, 0x94,
                0xa0, 0xdd, 0x4a, 0xa6, 0x22, 0x93, 0xa9, 0xff,
                0xb5, 0x2f, 0x4f, 0x61, 0xe9, 0x2b, 0x01, 0x00,
                0x57, 0x02, 0xed, 0x3e, 0xd8, 0x57, 0x71, 0xd5,
                0x37, 0x0e, 0x51, 0xd8, 0x66, 0x1b, 0x65, 0xd5,
                0xd9, 0x73, 0x53, 0xe5, 0x49, 0x7c, 0xa5, 0x89,
                0xd3, 0x4d, 0x1f, 0x43, 0xae, 0xba, 0x0c, 0x41,
                0xa4, 0xc7, 0xa9, 0x8f, 0x33, 0xa6, 0x9a, 0x3f,
                0xdf, 0x9a, 0x68, 0xfa, 0x1d, 0x75, 0xd0, 0x62,
                0x0d, 0x26, 0x3d, 0x4c, 0x79, 0xa6, 0x8f, 0xbe,
                0xd0, 0x01, 0x77, 0xfe, 0x8d, 0x48, 0xe6, 0x2b,
                0x03, 0xee, 0x69, 0x7e, 0x8d, 0x48, 0xe6, 0x2b,
                0x1e, 0x0b, 0x1d, 0x7f, 0x46, 0xa4, 0x73, 0x15,
                0x81, 0xd7, 0x54, 0xdf, 0x5f, 0x2c, 0x7c, 0xfd,
                0xf6, 0x80, 0x0b, 0xbd, 0xf4, 0x3a, 0xeb, 0xa0,
                0xc4, 0x1a, 0x4c, 0x7a, 0x98, 0x41, 0xa6, 0xa8,
                0xb2, 0x2c, 0x5f, 0x24, 0x9c, 0x75, 0x4c, 0x5f,
                0xbe, 0xf0, 0x46, 0xcf, 0xdf, 0x68, 0x00, 0xbb,
                0xff, 0x40, 0x8a, 0x41, 0x48, 0xb4, 0xa5, 0x49,
                0x27, 0x59, 0x06, 0x49, 0x7f, 0x83, 0xa8, 0xf5,
                0x17, 0x40, 0x8a, 0x41, 0x48, 0xb4, 0xa5, 0x49,
                0x27, 0x5a, 0x93, 0xc8, 0x5f, 0x86, 0xa8, 0x7d,
                0xcd, 0x30, 0xd2, 0x5f, 0x40, 0x8a, 0x41, 0x48,
                0xb4, 0xa5, 0x49, 0x27, 0x5a, 0xd4, 0x16, 0xcf,
                0x02, 0x3f, 0x31, 0x40, 0x8a, 0x41, 0x48, 0xb4,
                0xa5, 0x49, 0x27, 0x5a, 0x42, 0xa1, 0x3f, 0x86,
                0x90, 0xe4, 0xb6, 0x92, 0xd4, 0x9f, 0x50, 0x8d,
                0x9b, 0xd9, 0xab, 0xfa, 0x52, 0x42, 0xcb, 0x40,
                0xd2, 0x5f, 0xa5, 0x23, 0xb3, 0x51, 0x90, 0xb7,
                0xaf, 0xd1, 0x6a, 0xfb, 0xed, 0x00, 0x17, 0x7f,
                0xea, 0xcb, 0x7e, 0xfb, 0x40, 0x05, 0xde }
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