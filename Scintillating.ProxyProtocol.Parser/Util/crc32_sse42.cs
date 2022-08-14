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

// crc32_4k_fusion Adapted from Pete Cawley’s https://www.corsix.org/content/fast-crc32c-4k

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Sse2 = System.Runtime.Intrinsics.X86.Sse2;
using Sse41 = System.Runtime.Intrinsics.X86.Sse41;
using Sse42 = System.Runtime.Intrinsics.X86.Sse42;
using Pclmulqdq = System.Runtime.Intrinsics.X86.Pclmulqdq;
using System.Runtime.Intrinsics;

namespace Scintillating.ProxyProtocol.Parser.Util;

[ExcludeFromCodeCoverage(Justification = "SSE4.2 CRC32C is machine dependent.")]
internal static unsafe class crc32_sse42
{
    // CRC-32C (iSCSI) polynomial in reversed bit order.
    private const uint POLY = 0x82f63b78;

    // Block sizes for three-way parallel crc computation.
    // LONG and SHORT must both be powers of two.
    private const int LONG = 128;

    private const int SHORT = 64;
    private const int TABLE_SIZE = 256;
    private const int TABLE_LENGTH = 4 * TABLE_SIZE;

    // Tables for updating a crc for LONG, 2 * LONG, SHORT and 2 * SHORT bytes
    // of value 0 later in the input stream, in the same way that the hardware
    // would, but in software without calculating intermediate steps.
    private static uint[]? crc32c_long;
    private static uint* ptr_crc32c_long;

    private static uint[]? crc32c_2long;
    private static uint* ptr_crc32c_2long;

    private static uint[]? crc32c_short;
    private static uint* ptr_crc32c_short;

    private static uint[]? crc32c_2short;
    private static uint* ptr_crc32c_2short;

    // Use ModuleInitializer to avoid problems with static ctor and/or beforefieldinit
    [ModuleInitializer]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SuppressMessage("Usage", "CA2255:The 'ModuleInitializer' attribute should not be used in libraries", Justification = "Hoist JIT checks for static initialization")]
    internal static void Initialize()
    {
        if (Sse42.IsSupported)
        {
            InitializeImpl();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeImpl()
    {
        ptr_crc32c_long = crc32c_zeros(LONG, out crc32c_long);
        ptr_crc32c_2long = crc32c_zeros(2 * LONG, out crc32c_2long);

        ptr_crc32c_short = crc32c_zeros(SHORT, out crc32c_short);
        ptr_crc32c_2short = crc32c_zeros(2 * SHORT, out crc32c_2short);
    }

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

    private static uint* crc32c_zeros(nuint len, out uint[] array)
    {
        Span<uint> op = stackalloc uint[32];
        ref uint rop = ref MemoryMarshal.GetReference(op);
        crc32c_zeros_op(op, len);
        uint[] zeros = GC.AllocateUninitializedArray<uint>(TABLE_LENGTH, pinned: true);
        fixed (uint* ptr = zeros)
        {
            for (uint n = 0; n < TABLE_SIZE; ++n)
            {
                ptr[0 * TABLE_SIZE + n] = gf2_matrix_times(ref rop, n);
                ptr[1 * TABLE_SIZE + n] = gf2_matrix_times(ref rop, n << 8);
                ptr[2 * TABLE_SIZE + n] = gf2_matrix_times(ref rop, n << 16);
                ptr[3 * TABLE_SIZE + n] = gf2_matrix_times(ref rop, n << 24);
            }

            array = zeros;
            return ptr;
        }
    } 

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint crc32c_shift(uint* ptr, uint crc)
    {
        return ptr[0 * TABLE_SIZE + (crc & 0xff)]
             ^ ptr[1 * TABLE_SIZE + ((crc >> 8) & 0xff)]
             ^ ptr[2 * TABLE_SIZE + ((crc >> 16) & 0xff)]
             ^ ptr[3 * TABLE_SIZE + (crc >> 24)];
    }

    public static uint sse42_crc32c(uint crc, byte* buffer, nuint length)
    {
        if (Sse42.X64.IsSupported && Pclmulqdq.IsSupported)
        {
            return sse42_crc32c_4k(crc, buffer, length);
        }

        if (Sse42.X64.IsSupported)
        {
            return sse42_crc32c_x86_64(crc, buffer, length);
        }

        return sse42_crc32c_x86(crc, buffer, length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint sse42_crc32c_4k(uint crc, byte* buffer, nuint length)
    {
        const nuint CHUNK_SIZE = 4096;

        while (length >= CHUNK_SIZE)
        {
            crc = crc32_4k_fusion(crc, buffer);

            buffer += CHUNK_SIZE;
            length -= CHUNK_SIZE;
        }

        if (length > 0)
        {
            crc = sse42_crc32c_x86_64(crc, buffer, length);
        }

        return crc;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint sse42_crc32c_x86_64(uint crc, byte* buf, nuint len)
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

                crc = (uint)(crc32c_shift(ptr_crc32c_long, crc) ^ crc0);
                crc1 = crc32c_shift(ptr_crc32c_long, (uint)crc1);
                crc = (uint)(crc32c_shift(ptr_crc32c_2long, crc) ^ crc1);
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

            crc = (uint)(crc32c_shift(ptr_crc32c_short, crc) ^ crc0);
            crc1 = crc32c_shift(ptr_crc32c_short, (uint)crc1);
            crc = (uint)(crc32c_shift(ptr_crc32c_2short, crc) ^ crc1);
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
    private static unsafe uint sse42_crc32c_x86(uint crc, byte* buf, nuint len)
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

                crc = crc32c_shift(ptr_crc32c_long, crc) ^ crc0;
                crc1 = crc32c_shift(ptr_crc32c_long, crc1);
                crc = crc32c_shift(ptr_crc32c_2long, crc) ^ crc1;
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

            crc = crc32c_shift(ptr_crc32c_short, crc) ^ crc0;
            crc1 = crc32c_shift(ptr_crc32c_short, crc1);
            crc = crc32c_shift(ptr_crc32c_2short, crc) ^ crc1;
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint crc32_4k_fusion(uint acc, byte* buf)
    {
        // Four chunks:
        //  Chunk A: 728 bytes from 0 through 728
        //  Chunk B: 728 bytes from 728 through 1456
        //  Chunk C: 720 bytes from 1456 through 2176
        //  Chunk D: 1920 bytes from 2176 through 4096
        // First block of 64 from D is easy.
        byte* buf2 = buf + 2176;
        Vector128<ulong> x1 = Sse2.LoadVector128((ulong*)buf2);
        Vector128<ulong> x2 = Sse2.LoadVector128((ulong*)(buf2 + 16));
        Vector128<ulong> x3 = Sse2.LoadVector128((ulong*)(buf2 + 32));
        Vector128<ulong> x4 = Sse2.LoadVector128((ulong*)(buf2 + 48));
        ulong acc_a = acc;
        ulong acc_b = 0;
        ulong acc_c = 0;
        // Parallel fold remaining blocks of 64 from D, and 24 from each of A/B/C.
        // k1 == magic(4*128+32-1)
        // k2 == magic(4*128-32-1)
        Vector128<ulong> k1k2 = Vector128.Create(/*k1*/ 0x740EEF02u, 0u, /*k2*/ 0x9E4ADDF8u, 0u)
            .As<uint, ulong>();
        byte* end = buf + 4096 - 64;

        do
        {
            acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)buf);
            Vector128<ulong> _x5 = Pclmulqdq.CarrylessMultiply(x1, k1k2, 0x00);
            acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728));
            x1 = Pclmulqdq.CarrylessMultiply(x1, k1k2, 0x11);
            acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2));
            Vector128<ulong> _x6 = Pclmulqdq.CarrylessMultiply(x2, k1k2, 0x00);
            acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)(buf + 8));
            x2 = Pclmulqdq.CarrylessMultiply(x2, k1k2, 0x11);
            acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728 + 8));
            Vector128<ulong> x7 = Pclmulqdq.CarrylessMultiply(x3, k1k2, 0x00);
            acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2 + 8));
            x3 = Pclmulqdq.CarrylessMultiply(x3, k1k2, 0x11);
            acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)(buf + 16));
            Vector128<ulong> x8 = Pclmulqdq.CarrylessMultiply(x4, k1k2, 0x00);
            acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728 + 16));
            x4 = Pclmulqdq.CarrylessMultiply(x4, k1k2, 0x11);
            acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2 + 16));
            _x5 = Sse2.Xor(_x5, Sse2.LoadVector128((ulong*)(buf2 + 64)));
            x1 = Sse2.Xor(x1, _x5);
            _x6 = Sse2.Xor(_x6, Sse2.LoadVector128((ulong*)(buf2 + 80)));
            x2 = Sse2.Xor(x2, _x6);
            x7 = Sse2.Xor(x7, Sse2.LoadVector128((ulong*)(buf2 + 96)));
            x3 = Sse2.Xor(x3, x7);
            x8 = Sse2.Xor(x8, Sse2.LoadVector128((ulong*)(buf2 + 112)));
            x4 = Sse2.Xor(x4, x8);
            buf2 += 64;
            buf += 24;
        } while (buf2 < end);
        // Next 24 bytes from A/B/C, and 8 more from A/B, then merge A/B/C.
        // Meanwhile, fold together D's four parallel streams.
        // k3 == magic(128+32-1)
        // k4 == magic(128-32-1)
        Vector128<ulong> k3k4 = Vector128.Create(/*k3*/ 0xF20C0DFEu, 0u, /*k4*/ 0x493C7D27u, 0u)
            .As<uint, ulong>();
        acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)buf);
        Vector128<ulong> x5 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x00);
        acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728));
        x1 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x11);
        acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2));
        Vector128<ulong> x6 = Pclmulqdq.CarrylessMultiply(x3, k3k4, 0x00);
        acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)(buf + 8));
        x3 = Pclmulqdq.CarrylessMultiply(x3, k3k4, 0x11);
        acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728 + 8));
        acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2 + 8));
        acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)(buf + 16));
        acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728 + 16));
        x5 = Sse2.Xor(x5, x2);
        acc_c = Sse42.X64.Crc32(acc_c, *(ulong*)(buf + 728 * 2 + 16));
        x1 = Sse2.Xor(x1, x5);
        acc_a = Sse42.X64.Crc32(acc_a, *(ulong*)(buf + 24));
        // k5 == magic(2*128+32-1)
        // k6 == magic(2*128-32-1)
        Vector128<ulong> k5k6 = Vector128.Create(/*k5*/ 0x3DA6D0CBu, 0u, /*k6*/ 0xBA4FC28Eu, 0u).As<uint, ulong>();
        x6 = Sse2.Xor(x6, x4);
        x3 = Sse2.Xor(x3, x6);
        x5 = Pclmulqdq.CarrylessMultiply(x1, k5k6, 0x00);
        acc_b = Sse42.X64.Crc32(acc_b, *(ulong*)(buf + 728 + 24));
        x1 = Pclmulqdq.CarrylessMultiply(x1, k5k6, 0x11);
        // kC == magic((        1920)*8-33)
        Vector128<ulong> kCk0 = Vector128.Create(/*kC*/ 0xF48642E9, 0, 0, 0)
              .As<uint, ulong>();
        Vector128<ulong> vec_c = Pclmulqdq.CarrylessMultiply(Sse2.ConvertScalarToVector128UInt32((uint)acc_c).As<uint, ulong>(), kCk0, 0x00);
        // kB == magic((    720+1920)*8-33)
        // kA == magic((728+720+1920)*8-33)
        Vector128<ulong> kAkB = Vector128.Create(/*kA*/ 0x155AD968u, 0u, /*kB*/ 0x2E7D11A7u, 0u).As<uint, ulong>();
        Vector128<ulong> vec_a = Pclmulqdq.CarrylessMultiply(Sse2.ConvertScalarToVector128UInt32((uint)acc_a).As<uint, ulong>(), kAkB, 0x00);
        Vector128<ulong> vec_b = Pclmulqdq.CarrylessMultiply(Sse2.ConvertScalarToVector128UInt32((uint)acc_b).As<uint, ulong>(), kAkB, 0x10);
        x5 = Sse2.Xor(x5, x3);
        x1 = Sse2.Xor(x1, x5);
        ulong abc = Sse2.X64.ConvertToUInt64(Sse2.Xor(Sse2.Xor(vec_c, vec_a), vec_b));
        // Apply missing <<32 and fold down to 32-bits.
        ulong crc = Sse42.X64.Crc32(0, Sse41.X64.Extract(x1, 0));
        crc = Sse42.X64.Crc32(crc, abc ^ Sse41.X64.Extract(x1, 1));
        return (uint)crc;
    }
}