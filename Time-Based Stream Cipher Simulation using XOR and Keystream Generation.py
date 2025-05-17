#Shanka Alwis 
#Thiveekshan Gunasegaran 


import hashlib
import time

def generate_keystream(desired_length):
    """Generates a keystream of the specified length."""
    seed = int(time.time() * 1000)
    result = seed * 2654435761
    result = result % 100000000
    hash_result = hashlib.sha256(str(result).encode()).hexdigest()
    keystream = hash_result[:7]

    # Repeat the keystream until it matches the desired length
    repeated_keystream = keystream * (desired_length // len(keystream)) + keystream[:desired_length % len(keystream)]

    return repeated_keystream

def convert_to_ascii_and_binary(keystream):
    ascii_values = [ord(char) for char in keystream]  # Convert to ASCII
    binary_values = [format(ascii, '08b') for ascii in ascii_values]  # Convert to binary
    return ascii_values, binary_values

def text_to_ascii(text):
    """Converts the given text to ASCII code."""
    ascii_codes = []
    for char in text:
        ascii_codes.append(ord(char))
    return ascii_codes

def ascii_to_binary(ascii_codes):
    """Converts a list of ASCII codes to 8-bit binary strings."""
    binary_strings = []
    for ascii_code in ascii_codes:
        binary_string = bin(ascii_code)[2:].zfill(8)  # Convert to binary, remove '0b' prefix, and pad to 8 bits
        binary_strings.append(binary_string)
    return binary_strings

def xor_binary_bitwise(binary_values1, binary_values2):
    """Performs XOR on two lists of binary strings bit by bit."""
    if len(binary_values1) != len(binary_values2):
        raise ValueError("Binary lists must have the same length.")

    result = []
    for i in range(len(binary_values1)):
        result.append(''.join(str(int(bit1) ^ int(bit2)) for bit1, bit2 in zip(binary_values1[i], binary_values2[i])))
    return result

def binary_to_ascii(binary_strings):
    """Converts a list of 8-bit binary strings to ASCII code."""
    ascii_codes = []
    for binary_string in binary_strings:
        ascii_code = int(binary_string, 2)
        ascii_codes.append(chr(ascii_code))
    return ''.join(ascii_codes)

print("############ Stream Cipher Demonstration ##############")
print(" ")

text = input("Please enter the plaintext message you would like to encrypt : ")

print("\n")
print("Encrypting text.......................")
print("\n")
# Print the original text
print("Plaintext:", text)
print(" ")

# Convert to ASCII and print
ascii_codes = text_to_ascii(text)
# print("ASCII codes:", ascii_codes) USED FOR TESTING

# Convert ASCII to 8-bit binary and print
binary_values_from_text = ascii_to_binary(ascii_codes)
# print("Binary strings:", binary_values_from_text) USED FOR TESTING

# Get the length of the text
text_length = len(text)

# Generate a keystream of the same length
keystream = generate_keystream(text_length)
print(f"The generated Keystream is : {keystream}")

# Convert keystream to ASCII and binary
keystream_ascii, keystream_binary = convert_to_ascii_and_binary(keystream)
# print(f"ASCII Values from Keystream: {keystream_ascii}") USED FOR TESTING
# print(f"Binary Values from Keystream: {keystream_binary}") USED FOR TESTING

# XOR the binary values bit by bit
result_binary = xor_binary_bitwise(binary_values_from_text, keystream_binary)
# print("XOR Result (bitwise):", result_binary) USED FOR TESTING
print(" ")
# Convert XOR result back to text
result_text = binary_to_ascii(result_binary)
print("Encrypted message (cipertext): ", result_text)
print(" ")

decryption=input("Would You like to decrypt the message ? Y/N ").strip().lower()
if decryption.lower()=='y':
    print("\n")
    print("Decrypting the text...")
    print("\n")
    # Convert result text to ASCII codes
    d_result_text_ascii = text_to_ascii(result_text)

    # print("ASCII codes of result text:", d_result_text_ascii) USED FOR TESTING
    # Convert ASCII codes to binary
    d_ascii_text_to_binary=ascii_to_binary(d_result_text_ascii)

    #print("Cipher text Result (binary):", d_ascii_text_to_binary) USED FOR TESTING
    while True : 

         keystream_input = input("Please enter the keystream that you have used for the encryption: ")
         if keystream_input==keystream:
             break
         else:
            print("\n")
            print("The keystream entered is incorrect.")
            
         # Convert result text to ASCII codes
    d_keystream_input = text_to_ascii(keystream_input)
         # print("ASCII codes of keystream_input:", d_keystream_input) USED FOR TESTING
                    
         # Convert ASCII codes to binary
    d_ascii_keystream_to_binary=ascii_to_binary(d_keystream_input)
         # print("Keystream input binary):", d_ascii_keystream_to_binary) USED FOR TESTING

         # XOR the binary values bit by bit
    d_XOR_result = xor_binary_bitwise(d_ascii_text_to_binary, d_ascii_keystream_to_binary)
         # print("XOR Result (bitwise):", d_XOR_result) USED FOR TESTING

        # Convert XOR result back to text
    d_result_text = binary_to_ascii(d_XOR_result)
    print(" ")
    print("Message decrypted successfully :", d_result_text)
    
elif decryption.lower()=='n':
    print("\n")
    print("Decryption process had been cancelled .")   
else:
    print("\n")
    print("Invalid input")    
