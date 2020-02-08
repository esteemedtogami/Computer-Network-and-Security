#################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Feb. 8, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a working implementation of AES-128
#  Round Keys. This was based on Chapter 2.4 of
#  "Introduction to Network Security: Theory and
#  Practice 2nd Edition" by Jie Wang and Zachary
#  Kissel. Specifically, this was prompted
#  by homework question 2.12
#################################################


def T(my_string, my_num):
    result = []

    result.append(str(hex(int(S(my_string[2:4]), 16) ^ int(m(my_num-1), 16))))
    result.append(S(my_string[4:6]))
    result.append(S(my_string[6:8]))
    result.append(S(my_string[0:2]))

    return "".join(result)


def m(j):
    if j == 0:
        return "00000001"
    elif j == 1:
        return "00000010"
    else:
        return M(m(j-1))


def M(my_string):
    my_val = my_string[0]
    result = []

    for i in range(1, 8):
        result.append(my_string[i])

    result.append(0)

    if my_val == 1:
        new_string = str(hex(int("".join(result), 16) ^ int("00011011", 16)))
        return new_string
    else:
        return "".join(result)


def S(my_string):
    #  S-Box for Round Key
    #           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    S_Box = [["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],  # 0
             ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],  # 1
             ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],  # 2
             ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],  # 3
             ["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],  # 4
             ["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],  # 5
             ["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],  # 6
             ["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],  # 7
             ["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],  # 8
             ["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],  # 9
             ["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],  # a
             ["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],  # b
             ["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],  # c
             ["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],  # d
             ["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],  # e
             ["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]]  # f

    x_coord = int(my_string[0], 16)
    y_coord = int(my_string[1], 16)
    return S_Box[x_coord][y_coord]


def main():
    K = "1234567890abcdef1234567890abcdef"
    W = []

    for i in range(4):
        W.append(K[i*8:((i*8)+8)])
        print("W", i, ":", W[i])

    for i in range(4, 8):
        hex_calc = ""
        if i % 4 == 0:
            #  So what this disaster of parentheses translates to is a lot of casting.
            #   The strings are cast to ints to do the xor, result is cast to hex to have
            #   the correct numbers, and then recast to strings.
            hex_calc = str(hex(int(W[i-4], 16) ^ int((T(W[i-1], (i/4))), 16)))
            W.append(hex_calc[2:len(hex_calc)])
            print("W", i, ":", W[i])
        else:
            hex_calc = str(hex(int(W[i-4], 16) ^ int(W[i-1], 16)))
            W.append(hex_calc[2:len(hex_calc)])
            print("W", i, ":", W[i])

    K1 = W[4:8]
    print("K1: " + "".join(K1))


main()
