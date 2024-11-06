from pwn import *
import copy
import os
import string
import random
from utils import *
from math import pi

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

format_string_specifiers = ['%', 's', 'p', 'd', 'c', 'u', 'x', 'n']
ascii_controls = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
                  '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11',
                  '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a',
                  '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x7f']

queue = []
found_paths = []

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(p, payload, filepath):
    p.sendline(payload)
    output = p.recvline()

    try: 
        output = p.recvline()
        if output == "":
            pass
        # A different traversal path has been found and hence it is added to the queue
        elif output not in found_paths:
            # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
            if not ("invalid" in output or "Invalid" in output):
                queue.append(payload) # Add the current payload into the queue
                found_paths.append(output) # Adds the output so we don't encounter it again and keep appending
                print_new_path_found()
    except:
        print("Exception in Recvline Caused")

    p.proc.stdin.close()

    code = p.poll(True)
    
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
    p = get_process(filepath)
    p.sendline(words)
    output = p.recvline()
    found_paths.append(output)

    for item in queue:
        for i in range(0, NUM_MUTATIONS):
            d = copy.deepcopy(item)
            if perform_mutation(filepath, d, i):
                print_crash_found()
                exit()

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data, i):
    if i == 0:
        print("> Testing Sending Nothing")
        if send_to_process(get_process(filepath), '', filepath):
            return True
    elif i == 1:
        if send_wordlist(filepath):
            return True
    elif i == 2:
        if flip_bits(filepath, data):
            return True
    elif i == 3:
        if add_random_bytes(filepath, data):
            return True
    elif i == 4:
        if add_long_strings_ascii(filepath, data):
            return True
    elif i == 5:
        if add_long_strings_printable(filepath, data):
            return True
    elif i == 6:
        if send_massive(filepath):
            return True
    elif i == 7:
        if send_format_strings(filepath):
            return True
    else:
        return False
    
'''
Using the defined wordlists we send a significant ammount of varying inputs
1. Naughty String Inputs
2. Number Mutation Inputs
'''
def send_wordlist(filepath):
    # Naughty String Wordlist
    with open('./wordlists/allnumber.txt', 'r') as file:
        for line in file:
            p = get_process(filepath)
            if send_to_process(p, line, filepath):
                file.close()
                return True
            
    file.close()

    # Naughty String Wordlist
    with open('./wordlists/naughtystrings.txt', 'r') as file:
        for line in file:
            p = get_process(filepath)
            if send_to_process(p, line, filepath):
                file.close()
                return True
            
    file.close()

    return False

'''
Sends the original payload but with random bits flipped
'''
def flip_bits(filepath, data):
    if is_str(data):
        bits = ustring_to_bits(data)
    else:
        bits = unumber_to_bits(data)

    for num in range(0, len(bits) * 50):
        flipped = uflip_bits(bits)
        back_to_string = ubits_to_string(flipped)

        p = get_process(filepath)
        if send_to_process(p, back_to_string, filepath):
            return True
    return False

'''
Inserts random bytes into the original payload
'''
def add_random_bytes(filepath, data):
    for num in range(0, 100):
        with_random = uadd_random_bytes(data, num)
        p = get_process(filepath)
        if send_to_process(p, with_random, filepath):
            return True
    return False

'''
Adds a random long string (ASCII) to the end of the current payload
'''
def add_long_strings_ascii(filepath, data):
    for num in range(0, 1000):
        longdata = data + (random.choice(string.ascii_letters) * num)
        p = get_process(filepath)
        if send_to_process(p, longdata, filepath):
            return True
    return False

'''
Adds a random long string (Printable) to the end of the current payload
'''
def add_long_strings_printable(filepath, data):
    for num in range(0, 1000):
        longdata = data + (random.choice(string.printable) * num)
        p = get_process(filepath)
        if send_to_process(p, longdata, filepath):
            return True
    return False

'''
Sends a couple massive strings
'''
def send_massive(filepath):
    for num in range(1, 11):
        massive = 'A' * (10000 * num)
        p = get_process(filepath)
        if send_to_process(p, massive, filepath):
            return True
    return False

'''
Generates a list of format strings using specifiers and a given 'index' to use that specifier on
'''
def send_format_strings(filepath):
    for num in range(0, 51):
        for format_spec in format_string_specifiers:
            if num is 0:
                format_string = f'%{format_spec}'
            else:
                format_string = f'%{num}${format_spec}'
            
            p = get_process(filepath)
            if send_to_process(p, format_string, filepath):
                return True
    return False

'''
Inserts all ASCII control characters into a random position in the string a certain number of times
'''
def insert_ascii_control(filepath, data):
    for control in ascii_controls:
        for num in range(0, 10):
            new = insert_random_character(data, control)
            p = get_process(filepath)
            if send_to_process(p, new, filepath):
                return True
    return False

'''
Helper
'''
def uadd_random_bytes(input_string: str, num_bytes: int) -> bytes:
    string_bytes = input_string.encode('utf-8')
    random_bytes = os.urandom(num_bytes)
    return string_bytes + random_bytes

'''
Helper
'''
def insert_random_character(s, c):
    index = random.randint(0, len(s))
    return s[:index] + c + s[index:]