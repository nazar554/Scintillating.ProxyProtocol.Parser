﻿using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Crc32 = System.Runtime.Intrinsics.Arm.Crc32;
using Sse42 = System.Runtime.Intrinsics.X86.Sse42;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal sealed partial class Crc32C : HashAlgorithm
{
    public const int SizeBits = sizeof(uint) * 8;

    private uint _crc;

    public Crc32C()
    {
        HashSizeValue = SizeBits;
        Initialize();
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        _crc = HashReflected(_crc, array, ibStart, cbSize);
    }

    protected override void HashCore(ReadOnlySpan<byte> source)
    {
        _crc = HashReflected(_crc, source);
    }

    protected override byte[] HashFinal() => BitConverter.GetBytes(~_crc);

    protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length < sizeof(uint))
        {
            bytesWritten = 0;
            return false;
        }

        Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), ~_crc);
        bytesWritten = sizeof(uint);
        return true;
    }

    public override void Initialize()
    {
        _crc = uint.MaxValue;
    }

    public static uint HashReflected(uint crc, ReadOnlySpan<byte> source)
    {
        return HashReflected(crc, ref MemoryMarshal.GetReference(source), (nuint)source.Length);
    }

    public static uint HashReflected(uint crc, byte[] array, int offset, int length)
    {
        return HashReflected(crc, ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(array), offset), (nuint)length);
    }

    public static uint HashReflected(uint crc, ref byte data, nuint length)
    {
        if (length == 0)
        {
            return crc;
        }

        if (Sse42.X64.IsSupported)
        {
            return HashCoreImplSse42x64(crc, ref data, length);
        }

        if (Sse42.IsSupported)
        {
            return HashCoreImplSse42(crc, ref data, length);
        }

        if (Crc32.Arm64.IsSupported)
        {
            return HashCoreImplAarch64(crc, ref data, length);
        }

        if (Crc32.IsSupported)
        {
            return HashCoreImplAarch32(crc, ref data, length);
        }

        return ThrowSoftwareFallbackNotImplemented();
    }

    [DoesNotReturn]
    private static uint ThrowSoftwareFallbackNotImplemented() => throw new NotImplementedException(
        "Software CRC32 fallback not yet implmented and hardware intrinsics are not supported on target architecture."
    );
}