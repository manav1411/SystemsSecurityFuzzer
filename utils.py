import random
import os

'''
Prints out the progress bar depending on input
'''
def progress_bar(current, total, bar_length=50):
    if not total: return # divide by 0 check

    fraction = current / total

    arrow = int(fraction * bar_length - 1) * '-' + '>'
    padding = int(bar_length - len(arrow)) * ' '

    ending = '\n' if current == total else '\r'

    print(f'Progress: [{arrow}{padding}] {int(fraction*100)}%', end=ending)

'''
Prints some facts
'''
def print_some_facts(numpaths, timetaken, signal="None"):
    print("Number of Unique Paths: " + str(numpaths) + " | Time Taken: " + str(timetaken) + " Seconds")
    print("Signal Received: ")

'''
Prints a line (duh)
'''
def print_line():
    print("=" * 67)

'''
Prints that a crash has been found
'''
def print_crash_found():
    print("#" * 67)
    print("#" * 22 + " Crashable Input Found " + "#" * 22)
    print("#" * 67)

'''
Prints that no crash has been found
'''
def print_no_crash_found():
    print("#" * 67)
    print("#" * 20 + " No Crashable  Input Found " + "#" * 20)
    print("#" * 67)

'''
Prints that a new path has been found
'''
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
def uflip_bits_random(bits, flip_prob=0.2):
    bit_list = list(bits)
    for i in range(len(bit_list)):
        if random.random() < flip_prob:
            bit_list[i] = '1' if bit_list[i] == '0' else '0'

    return ''.join(bit_list)

'''
Flips a bit at a position
'''
def uflip_bits_at(bits, index):
    bit_list = list(bits)
    flipped_bit = '1' if bit_list[index] == '0' else '0'
    return ''.join(bit_list[:index] + [flipped_bit] + bit_list[index + 1:])

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
def unumber_to_bits(number, bit_length=64):
    # Convert the number to binary and remove the '0b' prefix
    binary_representation = bin(number)[2:]
    
    # Optionally, pad the binary string to a specified bit length
    if bit_length:
        binary_representation = binary_representation.zfill(bit_length)
    
    return binary_representation

'''
Converts bits back to a number
'''
def ubits_to_number(bits):
     return int(bits, 2)

'''
Changes a byte at a given index to a specified byte
'''
def replace_byte_at(data, index, byte):
    # Convert byte to a string if it's an integer, and validate it
    if isinstance(byte, int):
        byte = chr(byte)
    
    # Convert data to a string if it is an integer
    if isinstance(data, int):
        data = data.to_bytes(64)
        new_data = data[:index] + byte.encode() + data[index + 1:]
        return int.from_bytes(new_data)
    else:
        if isinstance(data, bytes):
            new_data = data[:index] + byte + data[index + 1:]
        else:
            new_data = data[:index] + str(byte) + data[index + 1:]
    
    return new_data

'''
Adds random bytes
'''
def uadd_random_bytes(s, num_bytes):
    random_bytes = os.urandom(num_bytes)
    index = random.randint(0, len(s))
    if isinstance(s, bytes):
        return s[:index] + random_bytes + s[index:]
    else:
        b = s.encode()
        return b[:index] + random_bytes + b[index:]
