#!/usr/bin/env sage

import random
import hashlib
import binascii
import re

# text_to_bits(), xor(), add_padding(), HashThis(M) are all extra helper functions
# text_to_bits():   converts ascii characters to bitstring
# xor():            is a bitstring exclusive or function
# add_padding():    add random bits of input number to end of a given sequence
# HashThis(M):      Has an initial 32 bit vector which is succesively xor'd with every 32 
#                   bits of the input M. The message M is padded by being first converted to binary
#                   to complete to a length of 32x

# PUg(),PUu(), and UserSecretNo() are all User specific information

# Verifying() & Signing() is where the magic happens for signing the hashed message and then
# verifying the digital signature

# PUg(),PUu
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def xor(bit_string1,bit_string2):
    xor_result = ""
    for i in range(0,len(bit_string1)):
        xor_result += format(int(bit_string1[i])^int(bit_string2[i]))
    return xor_result

def add_padding(seq, num_bits):
    pad_size = num_bits - len(seq) 
    return [random.choice([0, 1]) for _ in range(pad_size)] + list(seq)

def HashThis(M):
    initVector = text_to_bits('engn')
    messg = text_to_bits(M)
    if len(messg)%32 != 0 : messg = add_padding(messg, len(messg) + (32-len(messg)%32))
    messg = ''.join([str(elem) for elem in messg])
    messg = re.findall('.{%d}' % 32, messg)
    for elem in messg:
        initVector = xor(elem,initVector)
    return int(initVector,2)

def PUg():
    L = -1
    while (L % 2 != 0): L = random.randrange(8,16)

    p = random_prime(2^L, lbound = 2^(L-1))
    pm1 = p-1
    divs = pm1.divisors()

    q = -1
    for numb in divs:
        if numb.is_prime() and numb.nbits() == 8:
            q = numb
            h = random.randrange(2,p-1)
            F = GF(p)
            g = (F(h)^((p-1)/q)) % p
            if (g>1): return p, q, g 
    return PUg()

def PRu(q):
    x = random.randrange(1,q)
    return x

def PUu(g,x,p):
    y = (g^x) % p
    return y

def UserSecretNo(q):
    k = random.randrange(1,q)
    return k

def Signing(g,k,p,q,M,x):

    r = mod(power_mod(int(g),int(k),int(p)),int(q))
    HM = HashThis(M)
    # kinv = int(k) ^ (-1)
    # hmpxr = float(int(HM) + int(x)*int(r))
    s = mod(int(int(k)^(-1)*float(int(HM)+int(x)*int(r))),q)
    return r,s,HM

def Verifying(s,q,HM,y,p):
    w = mod(s^(-1),int(q))
    u1 = mod(HM*w,int(q))
    u2 = mod((r*w),q)
    v = mod(mod((g^int(u1))*(y^int(u2)),p),q)
    return v

# Run the script here

M = "Hello my name is engin"
p,q,g = PUg()
x = PRu(q)
y = PUu(g,x,p)
k = UserSecretNo(q)
r,s,HM = Signing(g,k,p,q,M,x)
v = Verifying(s,q,HM,y,p)

print('-' * 50)
print('Global Public-Key Components')
print('p: ' + str(p))
print('q: ' + str(q))
print('g: ' + str(g))

print('-' * 50)
print("User Info")
print('1)   Private key (x): ' + str(x))
print('2)   Public key (y): ' + str(y))
print("3)   User's Per-Message Secret Number (k): " + str(k))

print('-' * 50)
print("Signin and Verification")
print('Signature (r,s): ' + '('+str(r) + ', ' + str(s) +')')
print('Test (v): ' + str(v))

print('-' * 50)
print('Result of verification was: ')
if v==r: print("Successss v equal to r!")
else: print("Failure v not equal to r!")
