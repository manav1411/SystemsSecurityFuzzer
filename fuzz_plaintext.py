import copy
import os
import string
import random
import subprocess
import time
import threading
from utils import *

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

'''
Queueing for code coverage
'''
queue = []
found_paths = []

'''
Timing Things
'''
start = 0
end = 0

'''
Threads for multithreading
'''
crashed = False
threads = []

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
    
    if code != 0:
        global crashed
        crashed = True
        end = time.time()
        write_crash_output(filepath, payload)
        progress_bar(1, 1)
        print_crash_found()
        print_some_facts(len(found_paths), end - start, get_signal(code))
        return True
    else:
        return False

'''
Main function call to begin fuzzing Plaintext input binaries
'''
def fuzz_plaintext(filepath, words):
    global start
    start = time.time()
    queue.append(words)

    # Do the first default payload to see what the intial output should be.
    send_to_process(str(words), filepath)

    for item in queue:
        global threads
        threads = []
        d = copy.deepcopy(item)
        if perform_mutation(filepath, d):
            return

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data):
    global crashed
    threads.append(threading.Thread(target=send_wordlist_naughty, args=(filepath, )))
    threads.append(threading.Thread(target=send_wordlist_number, args=(filepath, )))
    threads.append(threading.Thread(target=flip_bits, args=(filepath, data)))
    threads.append(threading.Thread(target=add_random_bytes, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_random_bytes, args=(filepath, data, 50)))
    threads.append(threading.Thread(target=add_long_strings_ascii, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_long_strings_ascii, args=(filepath, data, 500)))
    threads.append(threading.Thread(target=add_long_strings_printable, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_long_strings_printable, args=(filepath, data, 500)))
    threads.append(threading.Thread(target=send_massive, args=(filepath, )))
    threads.append(threading.Thread(target=send_format_strings, args=(filepath, )))
    
    while len(threads) > 0:
        t = threads.pop()
        t.start()

    print_line()
    numthreads = (threading.active_count() - 1) # We subtract the main thread
    workingThreads = 1

    while workingThreads:
        workingThreads = threading.active_count() - 1
        progress_bar(numthreads - workingThreads, numthreads)
        if crashed: 
            return True
    return False
    
'''
Using the defined wordlist we send a significant ammount of varying inputs
'''
def send_wordlist_number(filepath):
    global crashed
    print('> Sending Wordlist allnumber')
    with open('./wordlists/allnumber.txt', 'r') as file:
        for line in file:
            if crashed: 
                file.close()
                return
            if send_to_process(line, filepath):
                file.close()
                crashed = True
                return
            
    print("- Finished Sending All Numbers")

'''
Using the defined wordlist we send a significant ammount of varying inputs
'''
def send_wordlist_naughty(filepath):
    global crashed
    print("> Sending wordlist naughtystrings")
    with open('./wordlists/naughtystrings.txt', 'r') as file:
        for line in file:
            if crashed: 
                file.close()
                return
            if send_to_process(line, filepath):
                file.close()
                crashed = True
                return
            
    print("- Finished Sending All Strings")

'''
Sends the original payload but with random bits flipped
'''
def flip_bits(filepath, data):
    global crashed
    print("> Flipping bits")
    for num in range(0, len(data) * 50):
        d = copy.deepcopy(data)
        flipped = uflip_bits(ustring_to_bits(str(d)))
        if crashed: return
        if send_to_process(ubits_to_string(flipped), filepath):
            crashed = True
            return
    print("- Finished Bit Flipping")

'''
Inserts random bytes into the original payload
'''
def add_random_bytes(filepath, data, start):
    global crashed
    print("> Adding in random bytes")
    for _ in range(start, start + 500): # TODO: Increased this because it crashes plaintext3 sometimes
        for num in range(1, 11):
            d = copy.deepcopy(data)
            with_random = uadd_random_bytes(d, num)
            if crashed: return
            if send_to_process(str(with_random), filepath) or send_to_process(with_random, filepath):
                crashed = True
                return
    print("- Finished Random Bytes")

'''
Adds a random long string (ASCII) to the end of the current payload
'''
def add_long_strings_ascii(filepath, data, start):
    global crashed
    print("> Adding in long strings (ASCII)")
    for num in range(start, start + 500):
        d = copy.deepcopy(data)
        longdata = d + ((random.choice(string.ascii_letters).encode() * num))
        if crashed: return
        if send_to_process(str(longdata), filepath) or send_to_process(longdata, filepath):
            crashed = True
            return
    print(f"- Finished Long Strings ASCII (Start = {start})")

'''
Adds a random long string (Printable) to the end of the current payload
'''
def add_long_strings_printable(filepath, data, start):
    global crashed
    print("> Adding in long strings (Printable)")
    for num in range(start, start + 500):
        d = copy.deepcopy(data)
        longdata = d + (random.choice(string.printable).encode() * num)
        if crashed: return
        if send_to_process(str(longdata), filepath) or send_to_process(longdata, filepath):
            crashed = True
            return
    print(f"- Finished Long Strings Printable (Start = {start})")

'''
Sends a couple massive strings
'''
def send_massive(filepath):
    global crashed
    print("> Sending Massive Strings")
    for num in range(1, 101):
        massive = b'A' * (1000 * num)
        if crashed: return
        if send_to_process(str(massive), filepath) or send_to_process(massive, filepath):
            crashed = True
            return
    print("- Finished Sending Massive")

'''
Generates a list of format strings using specifiers and a given 'index' to use that specifier on
'''
def send_format_strings(filepath):
    global crashed
    print("> Sending Format String Payloads")
    for num in range(0, 51):
        for format_spec in format_string_specifiers:
            if num == 0:
                format_string = f'%{format_spec}'
            else:
                format_string = f'%{num}${format_spec}'
            
            if crashed: return
            if send_to_process(format_string, filepath):
                crashed = True
                return
    print("- Finished Sending Format Strings")

'''
Inserts all ASCII control characters into a random position in the string a certain number of times
'''
def insert_ascii_control(filepath, data):
    global crashed
    print("Sending ASCII Control Within Strings")
    for control in ascii_controls:
        for num in range(0, 10):
            d = copy.deepcopy(data)
            new = insert_random_character(d, control)
            if crashed: return
            if send_to_process(str(new), filepath) or send_to_process(new, filepath):
                crashed = True
                return
    print("- Finshed Sending ASCII Controls")

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
def insert_random_character(s, c):
    index = random.randint(0, len(s))
    return s[:index] + bytes(c) + s[index:]