Files contained within firectory:

    1) dsa.sage:

        Project creates a digital signature for user that is message specific. Signature is signed and the verified.

        Functions:
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

How to run:
1) cd Project\ 3/
2) Run sage by type 'sage'
3) type load('dsa.sage')
4) Results will be displayed
