#################################################
#  Copyright (C) 2020 Sam Pickell
#  Last Updated: Apr. 8, 2020
#  UML COMP 5610 Computer Network and Security
#
#  This is a working implementation of
#  DES, coded from scratch. This
#  was based on Chapter 2.2 of "Introduction
#  to Network Security: Theory and Practice
#  2nd Edition" by Jie Wang and Zachary
#  Kissel. Specifically, this was prompted
#  by homework question 2.4
#################################################


def convert_M(M_List):
    new_list = []

    #  Convert to bits
    for i in range(len(M_List)):
        new_list.append(format(ord(M_List[i]), '08b'))

    return "".join(new_list)


def convert_K(K_List):
    new_list = []

    #  Convert to bits
    for i in range(len(K_List)):
        new_list.append(format(ord(K_List[i]), '07b'))
        if K_List[i].count("1") % 2 == 0:
            new_list.append("0")
        else:
            new_list.append("1")

    return "".join(new_list)


def apply_IP(M):
    rev_M = list(M[len(M)::-1])
    my_mat = [["0", "0", "0", "0", "0", "0", "0", "0"], ["0", "0", "0", "0", "0", "0", "0", "0"],
              ["0", "0", "0", "0", "0", "0", "0", "0"], ["0", "0", "0", "0", "0", "0", "0", "0"],
              ["0", "0", "0", "0", "0", "0", "0", "0"], ["0", "0", "0", "0", "0", "0", "0", "0"],
              ["0", "0", "0", "0", "0", "0", "0", "0"], ["0", "0", "0", "0", "0", "0", "0", "0"]]
    counter = 0

    #  Create "A" Matrix
    counting_list = [6, 4, 2, 0, 7, 5, 3, 1]
    for i in range(len(counting_list)):
        for j in range(8):
            my_mat[counting_list[i]][j] = rev_M[counter]
            counter += 1

    #  Apply IP(M)
    final_list = []

    for i in range(len(counting_list)):
        for j in range(len(counting_list)):
            final_list.append(my_mat[counting_list[j]][counting_list[i]])

    return "".join(final_list)


def apply_IP_C(C):
    final_list = [C[39], C[7], C[47], C[15], C[55], C[23], C[63], C[31], C[38], C[6], C[46], C[14], C[54], C[22], C[62], C[30],
                  C[37], C[5], C[45], C[13], C[53], C[21], C[61], C[29], C[36], C[4], C[44], C[12], C[52], C[20], C[60], C[28],
                  C[35], C[3], C[43], C[11], C[51], C[19], C[59], C[27], C[34], C[2], C[42], C[10], C[50], C[18], C[58], C[26],
                  C[33], C[1], C[41], C[9], C[49], C[17], C[57], C[25], C[32], C[0], C[40], C[8], C[48], C[16], C[56], C[24]]

    return "".join(final_list)


def apply_IPKey(my_key):
    my_key_list = list(my_key)
    smaller_key = []
    counter = 1

    #  Convert every 8th bit from the key to an "8", to be removed later
    for i in range(len(my_key_list)):
        if counter % 8 == 0:
            smaller_key.append("8")
            counter = 1
        else:
            smaller_key.append(my_key_list[i])
            counter += 1

    #  Apply the IP Key encryption algorithm
    final_list = []
    next_index = 56

    for i in range(28):
        final_list.append(smaller_key[next_index])
        next_index = ((next_index - 8) % 65)

    next_index = 62

    for i in range(28, 52):
        final_list.append(smaller_key[next_index])
        next_index = ((next_index - 8) % 63)

    next_index = 27

    for i in range(52, 56):
        final_list.append(smaller_key[next_index])
        next_index = next_index - 8

    return "".join(final_list)


def string_l_shift(my_str):
    my_list = list(my_str)
    first_char = my_list[0]
    my_list.pop(0)
    my_list.append(first_char)

    return "".join(my_list)


def P_Key(my_U, my_V):
    my_list = list(my_U+my_V)
    final_list = []
    my_perm = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
               22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
               40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
               43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

    for i in range(len(my_perm)):
        final_list.append(my_list[my_perm[i]])

    return "".join(final_list)


def XOR_Encrypt(my_left, my_right, my_key):
    #  Perform the major part of Step 2 of DES Encryption
    my_EP = string_xor(EP_fun(my_right), my_key)
    my_S = S_fun(my_EP)
    my_P = P_fun(my_S)
    return string_xor(my_left, my_P)


def EP_fun(my_string):
    my_list = list(my_string)
    result = []
    next_index = 31
    counter = 0

    #  Perform expansion permutation
    for i in range(48):
        result.append(my_list[next_index])
        counter += 1
        if next_index == 31:
            next_index = 0
        else:
            next_index += 1
        if counter == 6:
            counter = 0
            next_index -= 2

    return "".join(result)


def string_xor(s1, s2):
    l1 = list(s1)
    l2 = list(s2)

    result = []

    #  Perform XOR
    for i in range(len(l1)):
        if l1[i] == l2[i]:
            result.append("0")
        else:
            result.append("1")

    return "".join(result)


def S_fun(my_string):
    #  S-Boxes (yes, all of them)
    S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
         [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
         [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
         [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
         [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
         [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
         [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    Y = []
    counter = 0

    #  Create 8 6-bit Blocks
    for i in range(8):
        Y.append(my_string[counter:(counter+6)])
        counter += 6

    #  Convert to 4-bit Blocks
    result = []

    for i in range(len(Y)):
        current_block = list(Y[i])
        x_coord = int((current_block[0] + current_block[5]), 2)
        y_coord = int((Y[i][1:5]), 2)
        base_10_num = S[i][x_coord][y_coord]
        val = format(base_10_num, '04b')
        result.append(val)

    return "".join(result)


def P_fun(my_string):
    my_list = list(my_string)
    order_list = [15, 6, 19, 10, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
                  1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

    #  Perform P(V) permutation
    result = []

    for i in range(len(order_list)):
        result.append(my_list[order_list[i]])

    return "".join(result)


def main():
    # Encryption
    encrypted_message = []

    # Key
    list_K = ["B", "L", "A", "C", "K", "H", "A", "T"]

    # User Message
    user_input = input("Please enter the message to be encrypted: ")

    # Make sure the message is divisible by 8
    if len(user_input) % 8 != 0:
        overage = 8 - (len(user_input) % 8)
        for i in range(overage):
            user_input = user_input + " "

    # The bulk of the encryption
    for i in range(len(user_input)//8):
        M = [user_input[(i*8)], user_input[(i*8) + 1], user_input[(i*8) + 2], user_input[(i*8) + 3],
             user_input[(i*8) + 4], user_input[(i*8) + 5], user_input[(i*8) + 6], user_input[(i*8) + 7]]
        M = convert_M(M)
        K = convert_K(list_K)

        IP_M = apply_IP(M)
        IP_Key = apply_IPKey(K)

        # Containers for U sub, V sub, K sub
        U_List = [IP_Key[0:28]]
        V_List = [IP_Key[28:56]]
        K_List = ["-1"]

        # Generate the keys we need
        for j in range(1, 16):
            U_List.append(string_l_shift(U_List[j-1]))
            V_List.append(string_l_shift(V_List[j - 1]))
            K_List.append(P_Key(U_List[j], V_List[j]))

        # Begin FCS Encryption
        L0 = IP_M[0:32]
        R0 = IP_M[32:len(IP_M)]

        L1 = R0
        R1 = XOR_Encrypt(L0, R0, K_List[1])

        for j in range(2, 16):
            L0 = L1
            R0 = R1

            L1 = R0
            R1 = XOR_Encrypt(L0, R0, K_List[j])

        encrypted_message.append(R1)
        encrypted_message.append(L1)

    print("Encrypted: ", "".join(encrypted_message))

    # Decryption
    decrypted_message = []

    encrypted_message = "".join(encrypted_message)

    # Reverse of Encryption
    for i in range((len(encrypted_message)) // 64):
        L_Prime_0 = encrypted_message[(i*64):(i*64 + 32)]
        R_Prime_0 = encrypted_message[(i*64 + 32):(i*64 + 64)]

        for j in range(1, 16):
            R_Prime_1 = XOR_Encrypt(L_Prime_0, R_Prime_0, K_List[(15-j+1)])
            L_Prime_1 = R_Prime_0

            R_Prime_0 = R_Prime_1
            L_Prime_0 = L_Prime_1

        decrypted_message.append(R_Prime_0)
        decrypted_message.append(L_Prime_0)

    decrypted_message = "".join(decrypted_message)

    # Convert back to ascii
    back_2_ascii = []

    for i in range(len(decrypted_message) // 64):
        back_2_ascii.append(apply_IP_C(decrypted_message[(i*64):((i+1)*64)]))

    # Convert back to message
    converted_message = []

    for i in range(len(back_2_ascii)):
        my_char = ""
        for j in range(8):
            my_char += chr(int(back_2_ascii[i][(j*8):((j+1)*8)], 2))
        converted_message.append(my_char)

    final_message = "".join(converted_message)
    print("Decrypted:", final_message)


main()
