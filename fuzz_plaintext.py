import copy
import os
import string
import random
import subprocess
import time
import threading
from utils import *
from payload_handler import *

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = True
SEE_OUTPUTS = False
MAX_THREADS = 10
TIMEOUT_SECONDS = 60

format_string_specifiers = ['%', 's', 'p', 'd', 'c', 'u', 'x', 'n']
ascii_controls = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
                  '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11',
                  '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a',
                  '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x7f']

'''
For code coverage
'''
found_paths = []

'''
Timing Things
'''
start = 0

'''
Threads for multithreading
'''
crashed = False
kill = False
threads = []

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(payload, filepath):
    # Sends the input as both text and bytes
    if isinstance(payload, bytes):
        pcrashed, poutput, pcode = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
        p2crashed, poutput, pcode = send_payload(payload.strip().decode(), filepath, SEE_INPUTS, SEE_OUTPUTS)
    else:
        pcrashed, poutput, pcode = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
        p2crashed, poutput, pcode = send_payload(payload.encode(), filepath, SEE_INPUTS, SEE_OUTPUTS)

    global crashed, kill
    if p2crashed or pcrashed:
        crashed = True

    if kill:
        return False

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(payload, filepath, pcode, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if poutput not in found_paths:
        found_paths.append(poutput)
        add_to_thread_queue(filepath, payload)

    return False

'''
Main function call to begin fuzzing Plaintext input binaries
'''
def fuzz_plaintext(filepath, words):
    w = words.decode()
    global start
    start = time.time()

    send_to_process(w, filepath)
    
    if perform_mutation():
        print_crash_found()
        return
    
    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()

'''
Adds a given payloads threads to the queue
'''
def add_to_thread_queue(filepath, data):
    global threads
    threads.append(threading.Thread(target=flip_bits, args=(filepath, data)))
    threads.append(threading.Thread(target=add_random_bytes, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_random_bytes, args=(filepath, data, 50)))
    threads.append(threading.Thread(target=add_long_strings_ascii, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_long_strings_printable, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=send_massive, args=(filepath, )))
    threads.append(threading.Thread(target=send_format_strings, args=(filepath, )))
    threads.append(threading.Thread(target=send_wordlist_naughty, args=(filepath, )))
    threads.append(threading.Thread(target=send_wordlist_number, args=(filepath, )))

'''
Continously runs threads until the program crashes or there
are no more processes to try and mutate
'''
def perform_mutation():
    global crashed, kill, threads, start
    while (len(threads)) > 0 or threading.active_count() > 1:
        if (time.time() - start > TIMEOUT_SECONDS):
            print("Timeout - Killing all Threads")
            kill = True
            return False
        if crashed: 
            return True
        elif threading.active_count() >= MAX_THREADS:
            continue
        elif len(threads) != 0:
            t = threads.pop()
            t.start()

    return False
    
'''
Using the defined wordlist we send a significant ammount of varying inputs
'''
def send_wordlist_number(filepath):
    global crashed, kill
    with open('./wordlists/allnumber.txt', 'r') as file:
        for line in file:
            if crashed or kill: 
                file.close()
                return
            if send_to_process(line, filepath):
                file.close()
                crashed = True
                return
            
'''
Using the defined wordlist we send a significant ammount of varying inputs
'''
def send_wordlist_naughty(filepath):
    global crashed, kill
    with open('./wordlists/naughtystrings.txt', 'r') as file:
        for line in file:
            if crashed or kill: 
                file.close()
                return
            if send_to_process(line, filepath):
                file.close()
                crashed = True
                return
            
'''
Sends the original payload but with random bits flipped
'''
def flip_bits(filepath, data):
    global crashed, kill
    for num in range(0, len(data) * 50):
        d = copy.deepcopy(data)
        flipped = uflip_bits_random(ustring_to_bits(str(d)))
        if crashed or kill: return
        if send_to_process(ubits_to_string(flipped), filepath):
            crashed = True
            return

'''
Inserts random bytes into the original payload
'''
def add_random_bytes(filepath, data, start):
    global crashed, kill
    for _ in range(start, start + 50): # TODO: Increased this because it crashes plaintext3 sometimes
        for num in range(1, 51):
            d = copy.deepcopy(data)
            with_random = uadd_random_bytes(d, num)
            if crashed or kill: return
            if send_to_process(with_random, filepath):
                crashed = True
                return

'''
Adds a random long string (ASCII) to the end of the current payload
'''
def add_long_strings_ascii(filepath, data, start):
    global crashed, kill
    for num in range(start, start + 250):
        d = copy.deepcopy(data)
        longdata = d + ((random.choice(string.ascii_letters) * num))
        if crashed or kill: return
        if send_to_process(longdata, filepath):
            crashed = True
            return

'''
Adds a random long string (Printable) to the end of the current payload
'''
def add_long_strings_printable(filepath, data, start):
    global crashed, kill
    for num in range(start, start + 250):
        d = copy.deepcopy(data)
        longdata = d + (random.choice(string.printable) * num)
        if crashed or kill: return
        if send_to_process(longdata, filepath):
            crashed = True
            return

'''
Sends a couple massive strings
'''
def send_massive(filepath):
    global crashed, kill
    for num in range(1, 101):
        massive = b'A' * (1000 * num)
        if crashed or kill: return
        if send_to_process(massive, filepath):
            crashed = True
            return
    
    for num in range(1, 101):
        massive = b'\x00' * (1000 * num)
        if crashed or kill: return
        if send_to_process(massive, filepath):
            crashed = True
            return
    
    for num in range(1, 101):
        massive = b'\xFF' * (1000 * num)
        if crashed or kill: return
        if send_to_process(massive, filepath):
            crashed = True
            return

'''
Generates a list of format strings using specifiers and a given 'index' to use that specifier on
'''
def send_format_strings(filepath):
    global crashed, kill
    for num in range(0, 51):
        for format_spec in format_string_specifiers:
            if num == 0:
                format_string = f'%{format_spec}'
            else:
                format_string = f'%{num}${format_spec}'
            
            if crashed or kill: return
            if send_to_process(format_string, filepath):
                crashed = True
                return

'''
Inserts all ASCII control characters into a random position in the string a certain number of times
'''
def insert_ascii_control(filepath, data):
    global crashed, kill
    for control in ascii_controls:
        for num in range(0, 10):
            d = copy.deepcopy(data)
            new = insert_random_character(d, control)
            if crashed or kill: return
            if send_to_process(str(new), filepath) or send_to_process(new, filepath):
                crashed = True
                return

'''
Helper
'''
def uadd_random_bytes(s, num_bytes):
    random_bytes = os.urandom(num_bytes)
    index = random.randint(0, len(s))
    b = s.encode()
    return b[:index] + random_bytes + b[index:]

'''
Helper
'''
def insert_random_character(s, c):
    index = random.randint(0, len(s))
    b = s.encode()
    return b[:index].encode() + bytes(c) + b[index:].encode()