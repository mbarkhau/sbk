# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Lookup tables for multiplication in GF(2**8)."""

EXP_LUT_STR = """
01 03 05 0f 11 33 55 ff 1a 2e 72 96 a1 f8 13 35
5f e1 38 48 d8 73 95 a4 f7 02 06 0a 1e 22 66 aa
e5 34 5c e4 37 59 eb 26 6a be d9 70 90 ab e6 31
53 f5 04 0c 14 3c 44 cc 4f d1 68 b8 d3 6e b2 cd
4c d4 67 a9 e0 3b 4d d7 62 a6 f1 08 18 28 78 88
83 9e b9 d0 6b bd dc 7f 81 98 b3 ce 49 db 76 9a
b5 c4 57 f9 10 30 50 f0 0b 1d 27 69 bb d6 61 a3
fe 19 2b 7d 87 92 ad ec 2f 71 93 ae e9 20 60 a0
fb 16 3a 4e d2 6d b7 c2 5d e7 32 56 fa 15 3f 41
c3 5e e2 3d 47 c9 40 c0 5b ed 2c 74 9c bf da 75
9f ba d5 64 ac ef 2a 7e 82 9d bc df 7a 8e 89 80
9b b6 c1 58 e8 23 65 af ea 25 6f b1 c8 43 c5 54
fc 1f 21 63 a5 f4 07 09 1b 2d 77 99 b0 cb 46 ca
45 cf 4a de 79 8b 86 91 a8 e3 3e 42 c6 51 f3 0e
12 36 5a ee 29 7b 8d 8c 8f 8a 85 94 a7 f2 0d 17
39 4b dd 7c 84 97 a2 fd 1c 24 6c b4 c7 52 f6
"""


LOG_LUT_STR = """
00 00 19 01 32 02 1a c6 4b c7 1b 68 33 ee df 03
64 04 e0 0e 34 8d 81 ef 4c 71 08 c8 f8 69 1c c1
7d c2 1d b5 f9 b9 27 6a 4d e4 a6 72 9a c9 09 78
65 2f 8a 05 21 0f e1 24 12 f0 82 45 35 93 da 8e
96 8f db bd 36 d0 ce 94 13 5c d2 f1 40 46 83 38
66 dd fd 30 bf 06 8b 62 b3 25 e2 98 22 88 91 10
7e 6e 48 c3 a3 b6 1e 42 3a 6b 28 54 fa 85 3d ba
2b 79 0a 15 9b 9f 5e ca 4e d4 ac e5 f3 73 a7 57
af 58 a8 50 f4 ea d6 74 4f ae e9 d5 e7 e6 ad e8
2c d7 75 7a eb 16 0b f5 59 cb 5f b0 9c a9 51 a0
7f 0c f6 6f 17 c4 49 ec d8 43 1f 2d a4 76 7b b7
cc bb 3e 5a fb 60 b1 86 3b 52 a1 6c aa 55 29 9d
97 b2 87 90 61 be dc fc bc 95 cf cd 37 3f 5b d1
53 39 84 3c 41 a2 6d 47 14 2a 9e 5d 56 f2 d3 ab
44 11 92 d9 23 20 2e 89 b4 7c b8 26 77 99 e3 a5
67 4a ed de c5 31 fe 18 0d 63 8c 80 c0 f7 70 07
"""


MUL_INVERSE_LUT_STR = """
00 01 8d f6 cb 52 7b d1 e8 4f 29 c0 b0 e1 e5 c7
74 b4 aa 4b 99 2b 60 5f 58 3f fd cc ff 40 ee b2
3a 6e 5a f1 55 4d a8 c9 c1 0a 98 15 30 44 a2 c2
2c 45 92 6c f3 39 66 42 f2 35 20 6f 77 bb 59 19
1d fe 37 67 2d 31 f5 69 a7 64 ab 13 54 25 e9 09
ed 5c 05 ca 4c 24 87 bf 18 3e 22 f0 51 ec 61 17
16 5e af d3 49 a6 36 43 f4 47 91 df 33 93 21 3b
79 b7 97 85 10 b5 ba 3c b6 70 d0 06 a1 fa 81 82
83 7e 7f 80 96 73 be 56 9b 9e 95 d9 f7 02 b9 a4
de 6a 32 6d d8 8a 84 72 2a 14 9f 88 f9 dc 89 9a
fb 7c 2e c3 8f b8 65 48 26 c8 12 4a ce e7 d2 62
0c e0 1f ef 11 75 78 71 a5 8e 76 3d bd bc 86 57
0b 28 2f a3 da d4 e4 0f a9 27 53 04 1b fc ac e6
7a 07 ae 63 c5 db e2 ea 94 8b c4 d5 9d f8 90 6b
b1 0d d6 eb c6 0e cf ad 08 4e d7 e3 5d 50 1e b3
5b 23 38 34 68 46 03 8c dd 9c 7d a0 cd 1a 41 1c
"""

EXP_LUT = [int(val, 16) for val in EXP_LUT_STR.split()]
LOG_LUT = [int(val, 16) for val in LOG_LUT_STR.split()]

MUL_INVERSE_LUT = [int(val, 16) for val in MUL_INVERSE_LUT_STR.split()]

# https://www.samiam.org/galois.html
#
# Multiplication can be more quickly done with a 256-byte log table and 256-byte
# exponentiation table. For example, to multiply 0x03 by 0x07 using the above tables,
# we do the following:
#
# - Look up 0x03 on the log table. We get 0x01
# - Look up 0x07 on the log table. We get 0xC6
# - Add up these two numbers together (using normal, not galois field, addition) mod 255.
#   (0x01 + 0xC6) % 255 = 0xC7
# - Look up the sum, 0xC7, on the exponentiation table. We get 0x09.

MUL_LUT = [
    [0 if (a == 0 or b == 0) else EXP_LUT[(LOG_LUT[a] + LOG_LUT[b]) % 255] for b in range(256)]
    for a in range(256)
]


def main() -> None:
    for table in [EXP_LUT, LOG_LUT, MUL_INVERSE_LUT]:
        print()
        for i, n in enumerate(table):
            mstr = hex(n)[2:]
            print(f"{mstr:>02}", end=" ")
            if (i + 1) % 16 == 0:
                print()
        print()


if __name__ == '__main__':
    main()
