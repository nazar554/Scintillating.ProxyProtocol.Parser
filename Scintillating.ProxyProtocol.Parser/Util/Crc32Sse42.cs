// Adapted from FreeBSD Project
// See sys/libkern/x86/crc32_sse42.c

/*
 * Derived from crc32c.c version 1.1 by Mark Adler.
 *
 * Copyright (C) 2013 Mark Adler
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the author be held liable for any damages arising from the
 * use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * Mark Adler
 * madler@alumni.caltech.edu
 */

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Sse42 = System.Runtime.Intrinsics.X86.Sse42;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal static class Crc32Sse42
{
    // CRC-32C (iSCSI) polynomial in reversed bit order.
    private const uint POLY = 0x82f63b78;

    // Block sizes for three-way parallel crc computation.
    // LONG and SHORT must both be powers of two.
    private const int LONG = 128;

    private const int SHORT = 64;
    private const int TABLE_SIZE = 256;

    // Tables for updating a crc for LONG, 2 * LONG, SHORT and 2 * SHORT bytes
    // of value 0 later in the input stream, in the same way that the hardware
    // would, but in software without calculating intermediate steps.
    private static readonly uint[,] crc32c_long = crc32c_zeros(LONG);

    private static readonly uint[,] crc32c_2long = crc32c_zeros(2 * LONG);
    private static readonly uint[,] crc32c_short = crc32c_zeros(SHORT);
    private static readonly uint[,] crc32c_2short = crc32c_zeros(2 * SHORT);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint gf2_matrix_times(ref uint mat, uint vec)
    {
        uint sum = 0;
        while (vec != 0)
        {
            if ((vec & 1) != 0)
            {
                sum ^= mat;
            }
            vec >>= 1;
            mat = ref Unsafe.Add(ref mat, 1);
        }
        return sum;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void gf2_matrix_square(Span<uint> square, ref uint mat)
    {
        for (int n = 0; n < square.Length; ++n)
        {
            square[n] = gf2_matrix_times(ref mat, Unsafe.Add(ref mat, n));
        }
    }

    private static void crc32c_zeros_op(Span<uint> even, nuint len)
    {
        ref uint reven = ref MemoryMarshal.GetReference(even);
        Span<uint> odd = stackalloc uint[32]; // odd-power-of-two zeros operator
        ref uint rodd = ref MemoryMarshal.GetReference(odd);

        // put operator for one zero bit in odd
        odd[0] = POLY; // CRC-32C polynomial
        uint row = 1;
        for (int n = 1; n < odd.Length; ++n)
        {
            odd[n] = row;
            row <<= 1;
        }

        // put operator for two zero bits in even
        gf2_matrix_square(even, ref rodd);

        // put operator for four zero bits in odd
        gf2_matrix_square(odd, ref reven);

        do
        {
            gf2_matrix_square(even, ref rodd);
            len >>= 1;
            if (len == 0)
                return;
            gf2_matrix_square(odd, ref reven);
            len >>= 1;
        }
        while (len != 0);

        odd.CopyTo(even);
    }

    private static uint[,] crc32c_zeros(nuint len)
    {
        Span<uint> op = stackalloc uint[32];
        ref uint rop = ref MemoryMarshal.GetReference(op);
        crc32c_zeros_op(op, len);
        uint[,] zeros = new uint[4, TABLE_SIZE];
        ref uint ptr = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetArrayDataReference(zeros));
        for (uint n = 0; n < TABLE_SIZE; ++n)
        {
            ref uint x = ref Unsafe.Add(ref ptr, 0 * TABLE_SIZE + n);
            x = gf2_matrix_times(ref rop, n);

            x = ref Unsafe.Add(ref ptr, 1 * TABLE_SIZE + n);
            x = gf2_matrix_times(ref rop, n << 8);

            x = ref Unsafe.Add(ref ptr, 2 * TABLE_SIZE + n);
            x = gf2_matrix_times(ref rop, n << 16);

            x = ref Unsafe.Add(ref ptr, 3 * TABLE_SIZE + n);
            x = gf2_matrix_times(ref rop, n << 24);
        }

        return zeros;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint crc32c_shift(uint[,] zeros, uint crc)
    {
        ref uint ptr = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetArrayDataReference(zeros));

        return Unsafe.Add(ref ptr, 0 * TABLE_SIZE + (crc & 0xff))
             ^ Unsafe.Add(ref ptr, 1 * TABLE_SIZE + ((crc >> 8) & 0xff))
             ^ Unsafe.Add(ref ptr, 2 * TABLE_SIZE + ((crc >> 16) & 0xff))
             ^ Unsafe.Add(ref ptr, 3 * TABLE_SIZE + (crc >> 24));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint ComputeHash(uint crc, byte* buffer, nuint length)
    {
        if (Sse42.X64.IsSupported)
        {
            return sse42_crc32c_x64(crc, buffer, length);
        }

        ValidateIsSupported();

        return sse42_crc32c(crc, buffer, length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateIsSupported()
    {
        if (Environment.Is64BitProcess)
        {
            throw new InvalidOperationException("Attempted to use " + nameof(sse42_crc32c) + " in a 64-bit process.");
        }

        if (!Sse42.IsSupported)
        {
            throw new InvalidOperationException("Attempted to use " + nameof(sse42_crc32c) + " without SSE4.2 support.");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe uint sse42_crc32c_x64(uint crc, byte* buf, nuint len)
    {
        const nuint align = 8;

        byte* next = buf;
        ulong crc0 = crc;

        while (len != 0 && ((nuint)next & (align - 1)) != 0)
        {
            crc0 = Sse42.Crc32((uint)crc0, *next);
            ++next;
            --len;
        }

        byte* end;

        if (LONG > SHORT)
        {
            crc = 0;
            while (len >= LONG * 3)
            {
                ulong crc1 = 0, crc2 = 0;
                end = next + LONG;

                do
                {
                    crc0 = Sse42.X64.Crc32(crc0, *(ulong*)next);
                    crc1 = Sse42.X64.Crc32(crc1, *(ulong*)(next + LONG));
                    crc2 = Sse42.X64.Crc32(crc2, *(ulong*)(next + LONG * 2));
                    next += align;
                }
                while (next < end);

                crc = (uint)(crc32c_shift(crc32c_long, crc) ^ crc0);
                crc1 = crc32c_shift(crc32c_long, (uint)crc1);
                crc = (uint)(crc32c_shift(crc32c_2long, crc) ^ crc1);
                crc0 = crc2;
                next += LONG * 2;
                len -= LONG * 3;
            }
            crc0 ^= crc;
        }

        crc = 0;

        // Do the same thing, but now on SHORT*3 blocks for the remaining data
        // less than a LONG*3 block
        while (len >= SHORT * 3)
        {
            ulong crc1 = 0, crc2 = 0;
            end = next + SHORT;

            do
            {
                crc0 = Sse42.X64.Crc32(crc0, *(ulong*)next);
                crc1 = Sse42.X64.Crc32(crc1, *(ulong*)(next + SHORT));
                crc2 = Sse42.X64.Crc32(crc2, *(ulong*)(next + SHORT * 2));
                next += align;
            }
            while (next < end);

            crc = (uint)(crc32c_shift(crc32c_short, crc) ^ crc0);
            crc1 = crc32c_shift(crc32c_short, (uint)crc1);
            crc = (uint)(crc32c_shift(crc32c_2short, crc) ^ crc1);
            crc0 = crc2;
            next += SHORT * 2;
            len -= SHORT * 3;
        }
        crc0 ^= crc;

        end = next + (len - (len & (align - 1)));
        while (next < end)
        {
            crc0 = Sse42.X64.Crc32(crc0, *(ulong*)next);
            next += align;
        }
        len &= align - 1;

        while (len-- != 0)
        {
            crc0 = Sse42.Crc32((uint)crc0, *next);
            ++next;
        }

        return (uint)crc0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe uint sse42_crc32c(uint crc, byte* buf, nuint len)
    {
        const nuint align = 4;

        byte* next = buf;
        uint crc0 = crc;

        while (len != 0 && ((nuint)next & (align - 1)) != 0)
        {
            crc0 = Sse42.Crc32(crc0, *next);
            ++next;
            --len;
        }

        byte* end;

        if (LONG > SHORT)
        {
            crc = 0;
            while (len >= LONG * 3)
            {
                uint crc1 = 0, crc2 = 0;
                end = next + LONG;

                do
                {
                    crc0 = Sse42.Crc32(crc0, *(uint*)next);
                    crc1 = Sse42.Crc32(crc1, *(uint*)(next + LONG));
                    crc2 = Sse42.Crc32(crc2, *(uint*)(next + LONG * 2));
                    next += align;
                }
                while (next < end);

                crc = crc32c_shift(crc32c_long, crc) ^ crc0;
                crc1 = crc32c_shift(crc32c_long, crc1);
                crc = crc32c_shift(crc32c_2long, crc) ^ crc1;
                crc0 = crc2;
                next += LONG * 2;
                len -= LONG * 3;
            }
            crc0 ^= crc;
        }

        crc = 0;

        // Do the same thing, but now on SHORT*3 blocks for the remaining data
        // less than a LONG*3 block
        while (len >= SHORT * 3)
        {
            uint crc1 = 0, crc2 = 0;
            end = next + SHORT;

            do
            {
                crc0 = Sse42.Crc32(crc0, *(uint*)next);
                crc1 = Sse42.Crc32(crc1, *(uint*)(next + SHORT));
                crc2 = Sse42.Crc32(crc2, *(uint*)(next + SHORT * 2));
                next += align;
            }
            while (next < end);

            crc = crc32c_shift(crc32c_short, crc) ^ crc0;
            crc1 = crc32c_shift(crc32c_short, crc1);
            crc = crc32c_shift(crc32c_2short, crc) ^ crc1;
            crc0 = crc2;
            next += SHORT * 2;
            len -= SHORT * 3;
        }
        crc0 ^= crc;

        end = next + (len - (len & (align - 1)));
        while (next < end)
        {
            crc0 = Sse42.Crc32(crc0, *(uint*)next);
            next += align;
        }
        len &= align - 1;

        while (len-- != 0)
        {
            crc0 = Sse42.Crc32(crc0, *next);
            ++next;
        }

        return crc0;
    }
}