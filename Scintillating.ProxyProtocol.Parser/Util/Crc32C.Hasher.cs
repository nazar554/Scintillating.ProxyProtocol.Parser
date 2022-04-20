using System.Buffers.Binary;
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
                _crc = ComputeHash(_crc, buffer, length);
            }
        }

        public unsafe void HashCore(ReadOnlySpan<byte> source)
        {
            if (!source.IsEmpty)
            {
                _crc = ComputeHash(_crc, source);
            }
        }

        public void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (cbSize != 0)
            {
                _crc = ComputeHash(_crc, new ReadOnlySpan<byte>(array, ibStart, cbSize));
            }
        }

        private static unsafe uint ComputeHash(uint crc, byte* buffer, nuint length)
        {
            if (Sse42.IsSupported)
            {
                return ComputeHashSse42(crc, buffer, length);
            }
            if (Crc32.IsSupported)
            {
                return ComputeHashArmV8(crc, buffer, length);
            }

            return ComputeHashFallback(crc, buffer, length);
        }

        private static uint ComputeHash(uint crc, ReadOnlySpan<byte> source)
        {
            unsafe
            {
                fixed (byte* ptr = &MemoryMarshal.GetReference(source))
                {
                    return ComputeHash(crc, ptr, (nuint)source.Length);
                }
            }
        }

        private static unsafe uint ComputeHashSse42(uint crc, byte* buffer, nuint length) => crc32_sse42.sse42_crc32c(crc, buffer, length);

        private static unsafe uint ComputeHashArmV8(uint crc, byte* buffer, nuint length) => pg_crc32c_armv8.pg_comp_crc32c_armv8(crc, buffer, length);

        private static unsafe uint ComputeHashFallback(uint crc, byte* buffer, nuint length) => pg_crc32c_sb8.pg_comp_crc32c_sb8(crc, buffer, length);

        public readonly uint HashFinalValue => ~HashValue;

        public readonly uint HashValue
        {
            get
            {
                if (Sse42.IsSupported)
                {
                    return _crc;
                }

                if (Crc32.IsSupported)
                {
                    return _crc;
                }

                if (BitConverter.IsLittleEndian)
                {
                    return _crc;
                }

                return BinaryPrimitives.ReverseEndianness(_crc);
            }
        }

        public readonly byte[] HashFinal() => BitConverter.GetBytes(HashFinalValue);

        public readonly bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < sizeof(uint))
            {
                bytesWritten = 0;
                return false;
            }

            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), HashFinalValue);
            bytesWritten = sizeof(uint);
            return true;
        }

        public void Initialize()
        {
            _crc = uint.MaxValue;
        }
    }
}