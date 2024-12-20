import io
import csv
import copy
import random
import string
import time
import threading
from utils import *
from payload_handler import *

'''
Switch to True if you want to see the inputs / outputs being sent to / received from the binary
'''
SEE_INPUTS = False
SEE_OUTPUTS = False

'''
Global constants (threading-related)
'''
MAX_THREADS = 8
TIMEOUT_SECONDS = 110

'''
Defines
'''
# MASSIVE_STRING = 'A' * 10000
# MASSIVE_P_STRING = '%P' * 10000
delimiters_mutations_arr = [
    " ", "%", "\n", "%n", "&=", "|=", "^=",
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
kill = False
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
def send_to_process(payload, filepath, delim=','):
    p = list_to_csv(payload, delim)
    _crashed, _output, _code = send_payload(p, filepath, SEE_INPUTS, SEE_OUTPUTS)
    
    global crashed, kill
    if _crashed:
        crashed = _crashed

    if kill:
        return False

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(p, filepath, _code, len(found_paths), time.time() - start)
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
    w = csv_to_list(words)

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
    threads.append(threading.Thread(target=add_rows, args=(data, filepath)))
    threads.append(threading.Thread(target=add_cols, args=(data, filepath)))
    threads.append(threading.Thread(target=add_cols_and_rows, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_data_ints, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_data_values_with_delimiters, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_delimiters, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits, args=(data, filepath, 10)))
    threads.append(threading.Thread(target=mutate_strings, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_index, args=(data, filepath, 1500)))
    threads.append(threading.Thread(target=send_format_strings, args=(data, filepath)))
    threads.append(threading.Thread(target=test_empty_cells, args=(data, filepath)))
    threads.append(threading.Thread(target=add_random_bytes, args=(data, filepath)))
    threads.append(threading.Thread(target=add_bytes_sequential, args=(data, filepath)))

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
Adds 1 - 100 New Rows
'''
def add_rows(data: list, filepath):
    global crashed, kill
    d = copy.deepcopy(data)
    rowlen = len(d[0])
    for i in range(1, 101):
        
        row = []
        for i in range(0, rowlen):
            row.append(random.choice(string.ascii_letters))

        d.append(row)

        if crashed or kill: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Adds 1 - 100 New Cols
'''
def add_cols(data: list, filepath):
    global crashed, kill
    d = copy.deepcopy(data)
    for i in range(1, 101):
        
        for row in d:
            row.append(random.choice(string.ascii_letters))

        if crashed or kill: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Adds both extra rows and columns at the same time
'''
def add_cols_and_rows(data: list, filepath):
    global crashed, kill
    d = copy.deepcopy(data)
    for i in range(1, 101):
        
        for row in d:
            row.append(random.choice(string.ascii_letters))

        rowlen = len(d[0])
        newrow = []
        for j in range(0, rowlen):
            newrow.append(random.choice(string.ascii_letters))

        d.append(newrow)

        if crashed or kill: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Changes every cell in the CSV to all defined num values
'''
def mutate_data_ints(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                with open('./wordlists/allnumber.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        
                        d[i][j] = line.strip()
                        
                        if crashed or kill:
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
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                for delim in delimiters_mutations_arr:
                    d = copy.deepcopy(data)
                    
                    d[i][j] = delim

                    if crashed or kill: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return
                    
'''
Mutates the delimiters for the CSV File
'''
def mutate_delimiters(data: list, filepath):
    global crashed, kill
    for delim in delimiters_mutations_arr:
        d = copy.deepcopy(data)
        
        if crashed or kill: return
        if send_to_process(d, filepath, delim):
            crashed = True
            return


'''
Flips bits of the values contained within the CSV
'''
def flip_bits(data: list, filepath, numflips):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                d = copy.deepcopy(data)
                curr = d[i][j]

                if is_str(curr):
                    bits = ustring_to_bits(curr)
                elif is_num(curr):
                    bits = unumber_to_bits(curr)
                else:
                    continue

                for num in range(0, numflips):
                    flipped = uflip_bits_random(bits)
                    back_to_string = ubits_to_string(flipped)

                    d[i][j] = back_to_string
                    
                    if crashed or kill: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return

'''
Mutates the strings within the CSV
'''
def mutate_strings(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                with open('./wordlists/naughtystrings.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        
                        d[i][j] = line.strip()
                        
                        if crashed or kill:
                            file.close()
                            return
                        if send_to_process(d, filepath):
                            file.close()
                            crashed = True
                            return
                    file.close()
    return

'''
Replaces each index and then each row with strings of given length 
'''
def mutate_index(data: list, filepath, length):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    # One cell at a time
    for i in range(0, height):
            for j in range (0, width):
                d = copy.deepcopy(data)
                    
                d[i][j] = 'A' * length

                if crashed or kill: return
                if send_to_process(d, filepath):
                    crashed = True
                    return
                
    # One row at a time
    for i in range(0, height):
            d2 = copy.deepcopy(data)
            for j in range (0, width):
                d2[i][j] = 'A' * length

            if crashed or kill: return
            if send_to_process(d2, filepath):
                crashed = True
                return

    return


'''
Sends format string payloads
'''
def send_format_strings(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                for num in [1, 15, 40, 100]:
                    d = copy.deepcopy(data)                    
                    d[i][j] = f'%{num}$s'

                    if crashed or kill: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return

'''
Tests emptying random cells within the CSV
'''
def test_empty_cells(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(height):
            for j in range (width):
                d = copy.deepcopy(data)

                del d[i][j]

                if crashed or kill: return
                if send_to_process(d, filepath):
                    crashed = True
                    return
    


'''
Adds random bytes to the elements of the CSV
'''
def add_random_bytes(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(height):
        for j in range(width):
            for num in range(1, 11):
                for _ in range(1, 11):
                    d = copy.deepcopy(data)
                    d[i][j] = uadd_random_bytes(d[i][j], _)

                    if crashed or kill: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return

'''
Sequentially adds bytes throughout the object
'''
def add_bytes_sequential(data: list, filepath):
    global crashed, kill
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
        for j in range(0, width):
            for _ in range(0, len(data[i][j])):
                d = copy.deepcopy(data)
                d[i][j] = replace_byte_at(d[i][j], _, b"'")

                if crashed or kill: return
                if send_to_process(d, filepath):
                    crashed = True
                    return
            
            for _ in range(0, len(data[i][j])):
                d = copy.deepcopy(data)
                d[i][j] = replace_byte_at(d[i][j], _, b"\xFF")

                if crashed or kill: return
                if send_to_process(d, filepath):
                    crashed = True
                    return
            
            for _ in range(0, len(data[i][j])):
                d = copy.deepcopy(data)
                d[i][j] = replace_byte_at(d[i][j], _, b"\x00")

                if crashed or kill: return
                if send_to_process(d, filepath):
                    crashed = True
                    return


# '''
# Replaces a random value with another random value
# '''
# def replace_random_with_value(string, replacement):
#     if not string:  # If the string is empty, return it as-is
#         return string

#     # Convert the string to a list of characters to modify it
#     string_list = list(string)

#     # Select a random index
#     random_index = random.randint(0, len(string_list) - 1)

#     # Replace the character at the selected index with '\0'
#     string_list[random_index] = replacement

#     # Join the list back into a string and return it
#     return ''.join(string_list)
