#################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Mar. 4, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a working implementation of a 16-bit
# XOR hash function. The main function is
# specifically configured for a homework problem,
# but could be easily reconfigured to accept user
# input. This was based on Chapter 4.1 of
# "Introduction to Network Security: Theory and
# Practice 2nd Edition" by Jie Wang and Zachary
# Kissel. Specifically, this was prompted by
# homework question 4.2
#################################################

import math
import random


# Hashing function
def hashify(my_string):
    my_list = []

    # Separate M into 16-bit blocks, padding the final block if len < 16
    for i in range(math.ceil(len(my_string)/16)):
        my_append = my_string[(i*16):((i+1)*16)]
        if i == (math.ceil(len(my_string)/16)) - 1:
            if len(my_append) < 16:
                for j in range(16-len(my_append)):
                    my_append += "1"
        my_list.append(my_append)

    my_hash = my_list[0]

    # Perform manual XOR on each character for each block
    for i in range(1, len(my_list)):
        temp_list = []
        for j in range(16):
            if my_hash[j] == my_list[i][j]:
                temp_list.append("0")
            else:
                temp_list.append("1")
        my_hash = "".join(temp_list)

    return my_hash


# Given a hash, return a sequence that could generate that hash
def unhashify(my_hash):
    first_half = []
    second_half = []

    for i in range(16):
        # If we encounter a 1, the bits shouldn't match
        if my_hash[i] == "1":
            temp = random.randrange(0, 2)
            if temp == 1:
                second_half.append("0")
            else:
                second_half.append("1")
            first_half.append(str(temp))
        # Otherwise we encounter a 0, meaning the bits should match
        else:
            first_half.append(my_hash[i])
            second_half.append(my_hash[i])

    first_half.append("".join(second_half))

    return "".join(first_half)

def main():
    M1 = unhashify("1001101000111010")
    M2 = unhashify("1001101000111010")
    M3 = unhashify("1001101000111010")
    M4 = unhashify("1001101000111010")
    print(M1)
    print(M2)
    print(M3)
    print(M4)

    H1 = hashify(M1)
    H2 = hashify(M2)
    H3 = hashify(M3)
    H4 = hashify(M4)
    print(H1)
    print(H2)
    print(H3)
    print(H4)


main()
