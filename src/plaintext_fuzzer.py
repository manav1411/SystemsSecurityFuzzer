import copy
import os
import string
import random
import subprocess
import time
from utils import *
from math import pi

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = False
PRINT_OUTPUTS = False

format_string_specifiers = ['%', 's', 'p', 'd', 'c', 'u', 'x', 'n']
ascii_controls = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
                  '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11',
                  '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a',
                  '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x7f']

queue = []
found_paths = []

# NO NOT CHANGE
no_output = False


'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(payload, filepath):
    if SEE_INPUTS:
        print(payload)
    
    try:
        process = subprocess.run(
            [filepath],
            input=payload,
            text=True,
            capture_output=True
        )
        
        # Capture the return code and output
        code = process.returncode
        output = process.stdout

        if PRINT_OUTPUTS:
            print(output)
        
    except Exception as e:
        print(e)
        return False
    
    if output == "":
        pass
    # A different traversal path has been found and hence it is added to the queue
    elif output not in found_paths:
        # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
        if not ("invalid" in output or "Invalid" in output):
            # Add the current payload into the queue
            queue.append(payload)

            # Adds the output so we don't encounter it again and keep appending 
            found_paths.append(output)
            print_new_path_found()
            time.sleep(1)
    
    if code != 0:
        write_crash_output(filepath, str(payload))
        return True
    else:
        return False

'''
Main function call to begin fuzzing Plaintext input binaries
'''
def fuzz_plaintext(filepath, words):
    queue.append(words)

    # Do the first default payload to see what the intial output should be.
    send_to_process(words, filepath)

    for item in queue:
        d = copy.deepcopy(item)
        if perform_mutation(filepath, d):
            print_crash_found()
            exit()

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data):
    if send_to_process('', filepath): return True
    if send_wordlist(filepath): return True
    if flip_bits(filepath, data): return True
    if add_random_bytes(filepath, data): return True
    if add_long_strings_ascii(filepath, data): return True
    if add_long_strings_printable(filepath, data): return True
    if send_massive(filepath): return True
    if send_format_strings(filepath): return True
    return False
    
'''
Using the defined wordlists we send a significant ammount of varying inputs
1. Naughty String Inputs
2. Number Mutation Inputs
'''
def send_wordlist(filepath):
    print('Sending Wordlist allnumber')
    with open('./src/wordlists/allnumber.txt', 'r') as file:
        for line in file:
            if send_to_process(line.strip(), filepath):
                file.close()
                return True
    file.close()

    print("Sending wordlist naughtystrings")
    with open('./src/wordlists/naughtystrings.txt', 'r') as file:
        for line in file:
            if send_to_process(line.strip(), filepath):
                file.close()
                return True
    file.close()

    return False

'''
Sends the original payload but with random bits flipped
'''
def flip_bits(filepath, data):
    print("Flipping bits")
    for num in range(0, len(data) * 50):
        flipped = uflip_bits(data, num)
        if send_to_process(flipped, filepath):
            return True
    return False

'''
Inserts random bytes into the original payload
'''
def add_random_bytes(filepath, data):
    print("Adding in random bytes")
    for num in range(0, 500): # TODO: Increased this because it crashes plaintext3 sometimes
        with_random = uadd_random_bytes(data, num)
        if send_to_process(with_random, filepath):
            return True
    return False

'''
Adds a random long string (ASCII) to the end of the current payload
'''
def add_long_strings_ascii(filepath, data):
    print("Adding in long strings (ASCII)")
    for num in range(0, 1000):
        longdata = data + (random.choice(string.ascii_letters).encode('utf-8') * num)
        if send_to_process(longdata, filepath):
            return True
    return False

'''
Adds a random long string (Printable) to the end of the current payload
'''
def add_long_strings_printable(filepath, data):
    print("Adding in long strings (Printable)")
    for num in range(0, 1000):
        longdata = data + (random.choice(string.printable).encode('utf-8') * num)
        if send_to_process(longdata, filepath):
            return True
    return False

'''
Sends a couple massive strings
'''
def send_massive(filepath):
    print("Sending Massive Strings")
    for num in range(1, 11):
        massive = b'A' * (10000 * num)
        if send_to_process(massive, filepath):
            return True
    return False

'''
Generates a list of format strings using specifiers and a given 'index' to use that specifier on
'''
def send_format_strings(filepath):
    print("Sending Format String Payloads")
    for num in range(0, 51):
        for format_spec in format_string_specifiers:
            if num == 0:
                format_string = f'%{format_spec}'.encode('utf-8')
            else:
                format_string = f'%{num}${format_spec}'.encode('utf-8')
            
            if send_to_process(format_string, filepath):
                return True
    return False

'''
Inserts all ASCII control characters into a random position in the string a certain number of times
'''
def insert_ascii_control(filepath, data):
    print("Sending ASCII Control Within Strings")
    for control in ascii_controls:
        for num in range(0, 10):
            new = insert_random_character(data, control)
            if send_to_process(new, filepath):
                return True
    return False

'''
Helper
'''
def uadd_random_bytes(s, num_bytes):
    random_bytes = os.urandom(num_bytes)
    index = random.randint(0, len(s))
    return s[:index] + random_bytes + s[index:]

'''
Helper
'''
def uflip_bits(data, num_bits):
    bit_arr = list(data)
    total_bits = len(bit_arr) * 8

    for i in range(num_bits):
        bit_pos = random.randint(0, total_bits - 1)
        byte_index = bit_pos // 8
        bit_index = bit_pos % 8

        bit_arr[byte_index] ^= (1 << bit_index)
    
    return bytes(bit_arr)

'''
Helper
'''
def insert_random_character(s, c):
    index = random.randint(0, len(s))
    return s[:index] + bytes(c) + s[index:]