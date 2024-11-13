import io
import csv
import copy
import random
import string
import time
import threading
from math import pi
from utils import *
from payload_handler import *

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

'''
Switch to True if you want to see the inputs / outputs being send to / received from the binary
'''
SEE_INPUTS = False
SEE_OUTPUTS = False
MAX_THREADS = 5

MASSIVE_STRING = 'A' * 10000
MASSIVE_P_STRING = '%P' * 10000

delimiters_mutations_arr = [
    "", "%", "\n", "%n", "%s", "%d", "&=", "|=", "^=",
    "<<=", ">>=", "=", "+=", "-=", "*=", "/=", "//=",
    "%=", "**=", ",", ".", ":", ";", "@", "(", ")", "{",
    "}", "[", "]", "\"", "\'", "\0"
]

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
threads = []

'''
Returns whether the given data is valid CSV or not
'''
def is_csv(words):
    try:
        csv.reader(words)
    except:
        return False
    return True

'''
Creates an array of arrays representing each row
E.g.
header,must,stay,intact
a,b,c,S
e,f,g,ecr
i,j,k,et

->
[['header', 'must', 'stay', 'intact'], ['a', 'b', 'c', 'S'], ['e', 'f', 'g', 'ecr'], ['i', 'j', 'k', 'et']]
'''
def csv_to_list(data):
    list = []
    f = io.StringIO(data)
    for row in csv.reader(f, delimiter=','):
        list.append(row)
    return list

'''
Does the opposite of above
E.g.
[['header', 'must', 'stay', 'intact'], ['a', 'b', 'c', 'S'], ['e', 'f', 'g', 'ecr'], ['i', 'j', 'k', 'et']]
->
header,must,stay,intact
a,b,c,S
e,f,g,ecr
i,j,k,et

'''
def list_to_csv(data, delimiter=','):
    csv = ''
    for row in data:
        newline = ''
        for ele in row:
            newline += f'{ele}' + delimiter
        csv += f'{newline[:-1]}\n'
    return csv + '\n'

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(payload, filepath):
    payload = list_to_csv(payload, ',')
    _crashed, _output, _code = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
    
    global crashed
    crashed = _crashed

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(payload, filepath, _code, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if _output not in found_paths:
        found_paths.append(_output)
        add_to_thread_queue(filepath, payload)

    return False

''' New Delim Version '''
def send_to_process_newdelim(payload, filepath, delim):
    payload = list_to_csv(payload, delim)
    _crashed, _output, _code = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
    
    global crashed
    crashed = _crashed

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(payload, filepath, _code, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if _output not in found_paths:
        found_paths.append(_output)
        add_to_thread_queue(filepath, payload)

    return False

'''
Main function call to begin fuzzing CSV input binaries
'''
def fuzz_csv(filepath, words):
    global start
    start = time.time()
    words = csv_to_list(words)

    send_to_process(words, filepath)

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
    threads.append(threading.Thread(target=add_rows, args=(data, filepath)))
    threads.append(threading.Thread(target=add_cols, args=(data, filepath)))
    threads.append(threading.Thread(target=add_cols_and_rows, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_data_ints, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_data_values_with_delimiters, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_delimiters, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits, args=(data, filepath, 50)))
    threads.append(threading.Thread(target=mutate_index, args=(data, filepath, 0)))
    threads.append(threading.Thread(target=mutate_index, args=(data, filepath, 500)))
    threads.append(threading.Thread(target=mutate_strings, args=(data, filepath)))

'''
Continously runs threads until the program crashes or there
are no more processes to try and mutate
'''
def perform_mutation():
    global crashed, threads
    while (len(threads)) > 0 and threading.active_count() > 1:
        if crashed: 
            return True
        elif threading.active_count() >= MAX_THREADS:
            continue
        elif len(threads) != 0:
            t = threads.pop()
            t.start()

    return False

'''
Adds 1 - 100 New Rows
'''
def add_rows(data: list, filepath):
    global crashed
    d = copy.deepcopy(data)
    rowlen = len(d[0])
    for i in range(1, 101):
        
        row = []
        for i in range(0, rowlen):
            row.append(random.choice(string.ascii_letters))

        d.append(row)

        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Adds 1 - 100 New Cols
'''
def add_cols(data: list, filepath):
    global crashed
    d = copy.deepcopy(data)
    for i in range(1, 101):
        
        for row in d:
            row.append(random.choice(string.ascii_letters))

        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Adds both extra rows and columns at the same time
'''
def add_cols_and_rows(data: list, filepath):
    global crashed
    d = copy.deepcopy(data)
    for i in range(1, 101):
        
        for row in d:
            row.append(random.choice(string.ascii_letters))

        rowlen = len(d[0])
        newrow = []
        for j in range(0, rowlen):
            newrow.append(random.choice(string.ascii_letters))

        d.append(newrow)

        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Changes every cell in the CSV to all defined num values
'''
def mutate_data_ints(data: list, filepath):
    global crashed
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                with open('./wordlists/allnumber.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        
                        d[i][j] = line.strip()
                        
                        if crashed:
                            file.close()
                            return
                        if send_to_process(d, filepath):
                            file.close()
                            crashed = True
                            return
                    file.close()
    return

'''
Changes every cell in the CSV to all defined delimiter values
'''
def mutate_data_values_with_delimiters(data: list, filepath):
    global crashed
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                for delim in delimiters_mutations_arr:
                    d = copy.deepcopy(data)
                    
                    d[i][j] = delim

                    if crashed: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return
                    
'''
Mutates the delimiters for the CSV File
'''
def mutate_delimiters(data: list, filepath):
    global crashed
    for delim in delimiters_mutations_arr:
        d = copy.deepcopy(data)
        
        if crashed: return
        if send_to_process_newdelim(d, filepath, delim):
            crashed = True
            return

'''
Flips bits of the values contained within the CSV
'''
def flip_bits(data: list, filepath, numflips):
    global crashed
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                d = copy.deepcopy(data)
                curr = d[i][j]

                if is_str(curr):
                    bits = ustring_to_bits(curr)
                else:
                    bits = unumber_to_bits(curr)

                for num in range(0, numflips):
                    flipped = uflip_bits_random(bits)
                    back_to_string = ubits_to_string(flipped)

                    d[i][j] = back_to_string

                    
                    if crashed: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return

'''
Mutates the strings within the CSV
'''
def mutate_strings(data: list, filepath):
    global crashed
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                with open('./wordlists/naughtystrings.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        
                        d[i][j] = line.strip()
                        
                        if crashed:
                            file.close()
                            return
                        if send_to_process(d, filepath):
                            file.close()
                            crashed = True
                            return
                    file.close()
    return

'''
Tries to add 1 - 1000 length strings in each index of the CSV
'''
def mutate_index(data: list, filepath, startNum):
    global crashed
    width = len(data[0])
    height = len(data)

    for x in range (startNum, startNum + 500):
        for i in range(0, height):
                for j in range (0, width):
                    d = copy.deepcopy(data)
                        
                    d[i][j] = 'A' * x

                    if crashed: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return
    return

'''
Replaces a random value with another random value
'''
def replace_random_with_value(string, replacement):
    if not string:  # If the string is empty, return it as-is
        return string

    # Convert the string to a list of characters to modify it
    string_list = list(string)

    # Select a random index
    random_index = random.randint(0, len(string_list) - 1)

    # Replace the character at the selected index with '\0'
    string_list[random_index] = replacement

    # Join the list back into a string and return it
    return ''.join(string_list)
