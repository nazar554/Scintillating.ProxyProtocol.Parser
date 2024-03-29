﻿using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Crc32 = System.Runtime.Intrinsics.Arm.Crc32;
using Sse42 = System.Runtime.Intrinsics.X86.Sse42;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal sealed partial class Crc32C
{
    public struct Hasher
    {
        public const int SizeBits = sizeof(uint) * 8;

        private uint _crc;

        public Hasher()
        {
            _crc = uint.MaxValue;
        }

        public Hasher(uint crc)
        {
            _crc = crc;
        }

        public unsafe void HashCore(byte* buffer, nuint length)
        {
            if (length != 0)
            {
                _crc = ComputeHashDispatch(_crc, buffer, length);
            }
        }

        public unsafe void HashCore(ReadOnlySpan<byte> source)
        {
            if (!source.IsEmpty)
            {
                _crc = ComputeHashImpl(_crc, source);
            }
        }

        public void HashCore(byte[] array, int ibStart, int cbSize) => HashCore(new ReadOnlySpan<byte>(array, ibStart, cbSize));

        public static unsafe uint ComputeHash(byte* buffer, nuint length)
        {
            uint crc = uint.MaxValue;
            if (length == 0)
            {
                return crc;
            }
            return ~GetHashValue(ComputeHashDispatch(crc, buffer, length));
        }

        public static unsafe uint ComputeHash(ReadOnlySpan<byte> source)
        {
            uint crc = uint.MaxValue;
            if (source.IsEmpty)
            {
                return crc;
            }
            return ~GetHashValue(ComputeHashImpl(crc, source));
        }

        public static unsafe uint ComputeHash(byte[] array, int ibStart, int cbSize) => ComputeHash(new ReadOnlySpan<byte>(array, ibStart, cbSize));

        [ExcludeFromCodeCoverage(Justification = "Intrinsics dispatch is machine dependent.")]
        private static unsafe uint ComputeHashDispatch(uint crc, byte* buffer, nuint length)
        {
            if (Sse42.IsSupported)
            {
                return crc32_sse42.sse42_crc32c(crc, buffer, length);
            }
            if (Crc32.IsSupported)
            {
                return pg_crc32c_armv8.pg_comp_crc32c_armv8(crc, buffer, length);
            }

            return pg_crc32c_sb8.pg_comp_crc32c_sb8(crc, buffer, length);
        }

        private static uint ComputeHashImpl(uint crc, ReadOnlySpan<byte> source)
        {
            unsafe
            {
                fixed (byte* ptr = &MemoryMarshal.GetReference(source))
                {
                    return ComputeHashDispatch(crc, ptr, (nuint)source.Length);
                }
            }
        }

        [ExcludeFromCodeCoverage(Justification = "Intrinsics dispatch is machine dependent.")]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint GetHashValue(uint crc)
        {
            if (Sse42.IsSupported)
            {
                return crc;
            }

            if (Crc32.IsSupported)
            {
                return crc;
            }

            if (BitConverter.IsLittleEndian)
            {
                return crc;
            }

            return BinaryPrimitives.ReverseEndianness(crc);
        }

        public readonly uint HashFinalValue => ~HashValue;

        public readonly uint HashValue => GetHashValue(_crc);

        public readonly byte[] HashFinal()
        {
            var destination = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(destination, HashFinalValue);
            return destination;
        }

        public readonly bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            bool success = BinaryPrimitives.TryWriteUInt32BigEndian(destination, HashFinalValue);
            bytesWritten = success ? sizeof(uint) : 0;
            return success;
        }

        public void Initialize()
        {
            _crc = uint.MaxValue;
        }
    }
}