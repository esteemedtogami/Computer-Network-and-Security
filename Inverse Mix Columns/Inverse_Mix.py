#################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Feb. 9, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a partially working implementation of
#  inverse mic from AES-128. This was based on
#  Chapter 2.4 of "Introduction to Network
#  Security: Theory and Practice 2nd Edition" by
#  Jie Wang and Zachary Kissel. Specifically,
#  this was prompted by homework question 2.15
#################################################


#  Importing my M function from AES_128_RK.py program
def M(my_string):
    my_val = my_string[0]
    result = []

    for i in range(1, len(my_string)):
        result.append(my_string[i])

    result.append("0")

    if my_val == "1":
        new_string = bin(int("".join(result), 2) ^ int("00011011", 2))[2:]
        return new_string
    else:
        return "".join(result)


def M1(my_a):
    return bin(int(M(M(M(my_a))), 2) ^ int(M(M(my_a)), 2) ^ int(M(my_a), 2))[2:]


def M2(my_a):
    return bin(int(M(M(M(my_a))), 2) ^ int(M(my_a), 2) ^ int(my_a, 2))[2:]


def M3(my_a):
    return bin(int(M(M(M(my_a))), 2) ^ int(M(M(my_a)), 2) ^ int(my_a, 2))[2:]


def M4(my_a):
    return bin(int(M(M(M(my_a))), 2) ^ int(my_a, 2))[2:]


def main():
    my_a = bin(int("8e", 16))[2:]
    my_b = bin(int("4d", 16))[2:]
    my_c = bin(int("a1", 16))[2:]
    my_d = bin(int("bc", 16))[2:]

    my_mat = []

    mat_val = bin((int(M1(my_a), 2)) ^ (int(M2(my_b), 2)) ^ (int(M3(my_c), 2)) ^ (int(M4(my_d), 2)))[2:]
    my_mat.append(mat_val)

    mat_val = bin((int(M4(my_a), 2)) ^ (int(M1(my_b), 2)) ^ (int(M2(my_c), 2)) ^ (int(M3(my_d), 2)))[2:]
    my_mat.append(mat_val)

    mat_val = bin((int(M3(my_a), 2)) ^ (int(M4(my_b), 2)) ^ (int(M1(my_c), 2)) ^ (int(M2(my_d), 2)))[2:]
    my_mat.append(mat_val)

    mat_val = bin((int(M2(my_a), 2)) ^ (int(M3(my_b), 2)) ^ (int(M4(my_c), 2)) ^ (int(M1(my_d), 2)))[2:]
    my_mat.append(mat_val)

    print(my_mat)

main()
