######################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Feb. 15, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a working implementation of a simplified
#  version of RC4. This was based on Chapter 2.7 of
#  "Introduction to Network Security: Theory and
#  Practice 2nd Edition" by Jie Wang and Zachary
#  Kissel. Specifically, this was prompted
#  by homework question 2.47
######################################################


def KSA(K, S):

    for i in range(0, 8):
        S.append(i)

    j = 0
    for i in range(0, 8):
        j = (j + S[i] + int(K[i % len(K)], 2)) % 8
        temp = S[i]
        S[i] = S[j]
        S[j] = temp


def SGA(K, S):
    i = 0
    j = 0

    for u in range(len(K)):
        K.pop(0)

    for u in range(len(S)):
        i = (i+1) % 8
        j = (j+S[i]) % 8
        temp = S[i]
        S[i] = S[j]
        S[j] = temp
        K.append(bin(S[(S[i]+S[j]) % 8]))


def main():
    my_key = "0110010110000011"
    M = "WHITEHAT"
    K = []
    S = []
    C = []

    for i in range(len(my_key)//8):
        K.append(my_key[(i*8):(i*8)+8])

    KSA(K, S)
    print("S:", S)

    SGA(K, S)
    print("K:", K)

    for i in range(len(M)):
        C.append(bin(ord(M[i]) ^ int(K[i], 2)))

    print("C:", C)


main()
