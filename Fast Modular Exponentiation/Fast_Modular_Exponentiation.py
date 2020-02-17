######################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Feb. 17, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a working implementation of fast modular
#  exponentiation. This was based on Chapter 3.2.4 of
#  "Introduction to Network Security: Theory and
#  Practice 2nd Edition" by Jie Wang and Zachary
#  Kissel. Specifically, this was prompted
#  by homework question 3.6
######################################################
import math


def fast_mod(A, N, X, K):

    G = []

    for i in range(K+1):
        G.append(-1)

    G[K] = A
    for i in range(K-1, -1, -1):
        if X[i] == "1":
            G[i] = (G[i] * A) % N
        else:
            G[i] = (G[i+1] * G[i+1]) % N

    return G[0]


def main():
    A = 101
    X = (str(bin(124))[2:])[::-1]
    N = 110
    K = int(math.log2(128))

    result = fast_mod(A, N, X, K)

    print(result)


main()
