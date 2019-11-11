#!/usr/bin/python

import binascii
import random
import string
import numpy as np
from textwrap import wrap

IP_ARRAY = ['10', '8', '6', '4', '2', '9', '7', '5', '3', '1']
INVERSE_IP_ARRAY = ['']*10 #['10','5','9','4','8','3','7','2','6','1']
KEYS = [] #[K1,K2,K3,K4,K5]

# Reads 10 characters of an input file
def read_10char(in_file): 
    char_10 = in_file.read(10)
    return char_10

# Finds the inverse of given IP
def Inverse_IP_Find(INITIAL_P_ARRAY): 
    size_array = len(INITIAL_P_ARRAY)
    for i in range(0, size_array) : 
        INVERSE_IP_ARRAY[int(INITIAL_P_ARRAY[i]) - 1] = str(i+1)

# Applies initial permution ['10', '8', '6', '4', '2', '9', '7', '5', '3', '1']
def IP(text_10char, INITIAL_P_ARRAY):
    permutated_Text = ""
    for index in INITIAL_P_ARRAY:
        permutated_Text += text_10char[int(index)-1]
    return permutated_Text

# Applies inverse of initial permutation ['10','5','9','4','8','3','7','2','6','1']
def Inverse_IP(bit_string, Inverse_IP):
    permutated_Text = ""
    bit_string_wrap = wrap(bit_string,8)
    for index in Inverse_IP:
        permutated_Text += bit_string_wrap[int(index)-1]
    return permutated_Text

# Encode input series of characters by using builtin ASCII values into a bitstring with '0b' removed
def char_to_bits(text='', encoding='ascii', errors='surrogatepass'):
    bits = [bin(ord(x))[2:].zfill(8) for x in text]
    text = ""
    for bit in bits:
        text += bit
    return text
    

# Encode input bitstring to ASCII value
def bits_to_char(bits, encoding='ascii', errors='surrogatepass'):
    return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(bits)]*8))

# Shift Right Rotate a bitstring with given number of rotations
def SRR(bit_string, rotation_no):
    bit_string_left = bit_string[:rotation_no]
    bit_string_right = bit_string[rotation_no:]
    return bit_string_right+bit_string_left

# Shift Left Rotate a bitstring with given number of rotations
def SLR(bit_string, rotation_no):
    bit_string_left = bit_string[:len(bit_string)-rotation_no]
    bit_string_right = bit_string[len(bit_string)-rotation_no:]
    return bit_string_right+bit_string_left

# Return XOR of input bitstring pair
def xor(bit_string1,bit_string2):
    xor_result = ""
    for i in range(0,len(bit_string1)):
        xor_result += format(int(bit_string1[i])^int(bit_string2[i]))
    return xor_result

# Generate Keys(K1,K2,K3,K4,K5) to be used for feistel cipher
def Key_Gen():
    twochar_gen = 'VA' # use 2 chars for generation of K1 matrix
    genchars_tobits = char_to_bits(twochar_gen) # convert char pair to bitsring
    split_bits = genchars_tobits[:4] + ';' + genchars_tobits[4:8] + ';' + genchars_tobits[8:12] + ';' + genchars_tobits[12:] 
    split_bits = " ".join(split_bits) #split bits and add spaces to convert into matrix with numpy(np)
    k1 = np.matrix(split_bits)
    k10t, k11t, k12t, k13t = np.transpose(k1[:,0]) , np.transpose(k1[:,1]), np.transpose(k1[:,2]), np.transpose(k1[:,3]) #get columns 0,1,2,3 and transpose to create vector arrays
    k10, k11, k12, k13 = str(k10t).strip('[]'), str(k11t).strip('[]'), str(k12t).strip('[]'), str(k13t).strip('[]') #strip the array []
    k31 = k13.replace(" ","")+k11.replace(" ","") #remove spaces
    k02 = k10.replace(" ","")+k12.replace(" ","")
    k01 = k10.replace(" ","")+k11.replace(" ","")
    k32 = k13.replace(" ","")+k12.replace(" ","") 
    k2, k3 = xor(k31,k02), xor(k01,k32) # Generate K2 = k1(31) xor k1(02), K3 = k1(01) xor k1(32) 
    k4, k5 = SLR(k2,3), SRR(k3,5) # Generate K4 by shifting left rotating 3 on K2, and K5 by shifting right rotating by 5 on K3 
    KEYS.append(k1),KEYS.append(k2),KEYS.append(k3),KEYS.append(k4),KEYS.append(k5) #Add generated keys to KEYS global variable

# Feistel Encryption algorithm for Project 1
def Feistel_Encryption():
    Inverse_IP_Find(IP_ARRAY) # Create inverse IP to be stored in global INVERSE_IP_ARRAY
    # Create two ciphertext files, ciphertext.txt for display encoded message and
    # ciphertext_bits.txt for using in decryption
    file_out_ascii = open("ciphertext.txt","w+")
    file_out_bits = open("ciphertext_bits.txt","w+")
    with open("message.txt", "r") as file_in:
        counter = 1
        while True:
            chars = file_in.read(10)    # Read input file by 10 character increments
            if not chars: break        # Exit if end of file
            chars = chars.ljust(10)     # Padding to 10 for IP consistency
            text = ""               #Temporary empty string to store encoded 10 characters         
            initP = IP(chars,IP_ARRAY)      # Apply initial permutation
            char_pairs = map(''.join, zip(*[iter(initP)]*2))    # Split 10 characters into pairs of 2
            for pair in char_pairs:
                bits = SRR(char_to_bits(pair),4)        #First encode character pair to bitstring then apply shift right rotate by 4 to character pair
                left_nibble = xor(xor(bits[:8],KEYS[2]),KEYS[3])    #First half of bitstring xor'd with K3 then result xor'd with K4
                right_nibble = xor(xor(bits[8:],KEYS[1]),KEYS[4])   #Second half of bitstring xor'd with K2 then result xor'd with K5
                text += left_nibble + right_nibble     #Swap and combine encoded bitstring halves into temporary text
            inverse_IP = Inverse_IP(text,INVERSE_IP_ARRAY) # After 10 characters are encoded to bitstring apply Inverse IP
            encoded_iIP = bits_to_char(inverse_IP) #encode the current bitstring to ascii values
            file_out_bits.write(inverse_IP + '\n') #write bit string into ciphertext_bits file
            # Write the to be displayed encoded bits to ascii in a different file by organizing it
            if counter == 20:
                file_out_ascii.write(encoded_iIP + '\n')   
                counter = 1
            else:
                file_out_ascii.write(encoded_iIP)
                counter += 1
    file_in.close
    file_out_ascii.close
    file_out_bits.close

# Feistel Decryption to proves Feistel Encryption works
def Feistel_Decryption():
    file_out = open("decrypt.txt", "w+")    # Open new file to write into and compare with original message later on
    with open("ciphertext_bits.txt", "r") as file_in: # Take encoded ciphertext_bits file from result of Feistel Encryption
        for line_bits in file_in: # Read file line by line
            middle_text = ""  # Temp string used for writing into out file
            inverse_Inverse_IP = Inverse_IP(line_bits,IP_ARRAY) # Apply initial permutation to line of bitstring
            line_split = [inverse_Inverse_IP[i:i+8] for i in range(0, len(inverse_Inverse_IP), 8)]  # Split bitstring into 8 bits
            line_split_combine2 = [''.join(x) for x in zip(line_split[0::2], line_split[1::2])] # Create pairs of 2 from all bit string
            for bits in line_split_combine2: # Apply inverse order of encryption (decrypt) series to bitstring nibbles obtained from pairs created previously
                block13_left, block13_right = bits[:8], bits[8:] # create left and right nibbles
                block9_right, block9_left = xor(block13_right,KEYS[4]), xor(block13_left,KEYS[3]) #right and left nibbles are swapped and now apply xor with K5 to rightnibble and K4 to left nibble
                block5_right, block5_left = xor(block9_right,KEYS[1]), xor(block9_left, KEYS[2]) #apply xor with K2 to rightnibble and K3 to left nibble
                block4 = block5_left + block5_right # combined nibbles
                block4_SLR4 = SLR(block4,4) #apply shift left rotate by 4 times
                bits_left, bits_right = block4_SLR4[:8], block4_SLR4[8:]
                middle_text += bits_to_char(bits_left)+bits_to_char(bits_right)      # generate ascii characters from bitstring and add in order to temp string     
            inverse_Initial_P = IP(middle_text,INVERSE_IP_ARRAY) # apply inverse IP
            file_out.write(inverse_Initial_P)   # add result of inverse IP to output file
    file_in.close
    file_out.close

def check_test(): # Opens original message and decryption result for checking if encryption and decryption are successful
    file_in1 = open("message.txt","r")
    file_in2 = open("decrypt.txt","r")
    if file_in1.read().strip() == file_in2.read().strip():
        print("You have successfully encrypted and decrypted back to original file content!!!")

def FesitelCipher(): # Fesitel Cipher that generates keys and uses them to encrypt/decrypt files
    Key_Gen()
    Feistel_Encryption()
    Feistel_Decryption()
    check_test()

if __name__ == "__main__":
    FesitelCipher()