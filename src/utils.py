from pwn import *
import random

context.log_level='warn'

def write_crash_output(filename, input):
    output_file = './fuzzer_output/bad_' + filename[11:] + '.txt'
    with open(output_file, 'w') as file:
        file.write(input)
        file.close()
    print(f"Writing Input: ( {input} ) to Output File : ( {output_file} )")

def get_process(filepath):
    return process(filepath, timeout=1.5)

def print_crash_found():
    print("#########################################")
    print("######### Crashable Input Found #########")
    print("#########################################")

def print_no_crash_found():
    print("#########################################")
    print("####### No Crashable  Input Found #######")
    print("#########################################")

def print_new_path_found():
    print("# == # == # == # ==== # == # == # == #")
    print("# == # == # New Path Found # == # == #")
    print("# == # == # Added to Queue # == # == #")
    print("# == # == # == # ==== # == # == # == #")

'''
Checks whether a given data is an int
'''
def is_num(data):
    return isinstance(data, int)

'''
Checks whether a given data is a str
'''
def is_str(data):
    return isinstance(data, str)

'''
Flips some random bits within some bits
'''
def uflip_bits(bits, flip_prob=0.2):
    # Convert the bit string into a list of characters
    bit_list = list(bits)

    # Iterate through the bit list and randomly flip bits
    for i in range(len(bit_list)):
        if random.random() < flip_prob:
            # Flip the bit (0 becomes 1, and 1 becomes 0)
            bit_list[i] = '1' if bit_list[i] == '0' else '0'

    # Join the list back into a string and return the result
    return ''.join(bit_list)

'''
Converts a string to bits
'''
def ustring_to_bits(input_string):
    return ''.join(format(ord(char), '08b') for char in input_string)

'''
Converts bits to a string
'''
def ubits_to_string(bits):
    return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(bits)]*8))

'''
Converts a number to bits
'''
def unumber_to_bits(number, bit_length=None):
    # Convert the number to binary and remove the '0b' prefix
    binary_representation = bin(number)[2:]
    
    # Optionally, pad the binary string to a specified bit length
    if bit_length:
        binary_representation = binary_representation.zfill(bit_length)
    
    return binary_representation