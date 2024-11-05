from pwn import *
import io
import csv
import copy
import random
import string
import signal
import datetime
import store
import multiprocessing
from math import pi
from utils import *

# Number of Total Mutations
NUM_MUTATIONS = 100

# Defines for Mutations
MASS_POS_NUM = 999999999999999999999999999999999999999999999999999999
MASS_NEG_NUM = -999999999999999999999999999999999999999999999999999999
EIGHT_BYTE = 9223372036854775808
MAX_INT_32 = 2147483647
MIN_INT_32 = -2147483648
MAX_INT_64 = 9223372036854775807
MIN_INT_64 = -9223372036854775808

num_mutations_arr = [
    MASS_NEG_NUM, MASS_POS_NUM, EIGHT_BYTE, MAX_INT_32,
    MAX_INT_64, MIN_INT_32, MIN_INT_64, MAX_INT_32 + 1,
    MAX_INT_64 + 1, MIN_INT_32 - 1, MIN_INT_64 - 1, pi
]

MASSIVE_STRING = 'A' * 10000
MASSIVE_P_STRING = '%P' * 10000

delimiters_mutations_arr = [
    "", "%", "\n", "%n", "%s", "%d", "&=", "|=", "^=",
    "<<=", ">>=", "=", "+=", "-=", "*=", "/=", "//=",
    "%=", "**=", ",", ".", ":", ";", "@", "(", ")", "{",
    "}", "[", "]", "\"", "\'", "\0"
]

processes = []
found_paths = []

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
def send_to_process(p, csv_payload, filepath):
    payload = list_to_csv(csv_payload, ',')
    p.sendline(payload)

    try:
        output = p.recvline()
    except:
        print("Something went wrong here")
        return False

    # A different traversal path has been found and hence it is added to the queue
    if output not in found_paths:
        found_paths.append(output) # Adds the output so we don't encounter it again and keep appending
        print("# == # == # New Path Found # == # == #")
        begin_fuzzing_process(filepath, payload)

    p.proc.stdin.close()

    code = p.poll(True)
    
    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False


'''
Use this when calling a new thread to start the mutation process from the beggining
Current implementation is that we start a new thread anytime a new traversal path is found
'''
def begin_fuzzing_process(filepath, words):
    t = multiprocessing.Process(target=fuzz_csv, args=[filepath, words, False])
    print("Starting New Thread")
    print(f"New Payload: {words}")

    t.start()
    processes.append(t)

'''
Call this once a crash input has been found to kill all threads
'''
def kill_processes():
    for t in processes:
        t.terminate()

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process_newdelim(p, csv_payload, filepath, delimiter):
    payload = list_to_csv(csv_payload, delimiter)
    p.sendline(payload)
    p.proc.stdin.close()

    code = p.poll(True)
    p.close()

    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

'''
Main function call to begin fuzzing CSV input binaries
'''
def fuzz_csv(filepath, words, do_default):
    if do_default:
        # Do the first default payload to see what the intial output should be.
        p = get_process(filepath)
        p.sendline(words)
        output = p.recvline()
        found_paths.append(output)

    for i in range(0, NUM_MUTATIONS):
        deepcopy = copy.deepcopy(csv_to_list(words))

        if perform_mutation(filepath, deepcopy, i):
            print_crash_found()
            kill_processes()
            exit()

    print_no_crash_found()

'''
Begins the mutation process with a range of CSV files
'''
def perform_mutation(filepath, data, i):
    if i == 0:
        print("> Testing Normal Payload")
        if send_to_process(get_process(filepath), data, filepath):
            return True
    elif i == 1:
        print("> Testing Empty Payload")
        if send_to_process(get_process(filepath), "", filepath):
            return True
    elif i == 2:
        if add_rows(data, filepath):
            return True
    elif i == 3:
        if add_cols(data, filepath):
            return True
    elif i == 4:
        if add_cols_and_rows(data, filepath):
            return True
    elif i == 5:
        if mutate_data_ints(data, filepath):
            return True
    elif i == 6:
        if mutate_data_values_with_delimiters(data, filepath):
            return True
    elif i == 7:
        if mutate_delimiters(data, filepath):
            return True
    elif i == 8:
        if flip_bits(data, filepath, 50):
            return True
    elif i == 9:
        if mutate_index(data, filepath):
            return True
    elif i == 10:
        if mutate_strings(data, filepath):
            return True
    elif i == 10:
        if stack_smash(filepath, 250):
            return True
    else:
        return False

'''
Adds 1 - 10 New Rows
'''
def add_rows(data: list, filepath):
    print("> Testing Adding Rows")
    d = copy.deepcopy(data)
    rowlen = len(d[0])
    for i in range(1, 101):
        p = get_process(filepath)

        row = []
        for i in range(0, rowlen):
            row.append(random.choice(string.ascii_letters))

        d.append(row)

        if send_to_process(p, d, filepath):
            return True

    return False

'''
Adds 1 - 10 New Cols
'''
def add_cols(data: list, filepath):
    print("> Testing Adding Columns")
    d = copy.deepcopy(data)
    for i in range(1, 101):
        p = get_process(filepath)

        for row in d:
            row.append(random.choice(string.ascii_letters))

        if send_to_process(p, d, filepath):
            return True

    return False

'''
Adds both extra rows and columns at the same time
'''
def add_cols_and_rows(data: list, filepath):
    print("> Testing Adding Rows and Columns")
    d = copy.deepcopy(data)
    for i in range(1, 101):
        p = get_process(filepath)
        for row in d:
            row.append(random.choice(string.ascii_letters))

        rowlen = len(d[0])
        newrow = []
        for j in range(0, rowlen):
            newrow.append(random.choice(string.ascii_letters))

        d.append(newrow)

        if send_to_process(p, d, filepath):
            return True

    return False

'''
Changes every cell in the CSV to all defined num values
'''
def mutate_data_ints(data: list, filepath):
    print("> Testing Mutating Cell Values to Different Numbers")
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                for num in num_mutations_arr:
                    d = copy.deepcopy(data)
                    p = get_process(filepath)
                    d[i][j] = num

                    if send_to_process(p, d, filepath):
                        return True

                for x in range(0, 10):
                    if not is_num(data[i][j]):
                        continue
                    d = copy.deepcopy(data)
                    p = get_process(filepath)
                    curr = d[i][j]

                    if x == 0:
                        d[i][j] = int(curr)
                    elif x == 1:
                        d[i][j] = curr * 1.0
                    elif x == 2:
                        d[i][j] = curr * -1
                    elif x == 3:
                        d[i][j] = str(curr)
                    else:
                        p.proc.stdin.close()
                        break

                    if send_to_process(p, d, filepath):
                        return True
    return False

'''
Changes every cell in the CSV to all defined delimiter values
'''
def mutate_data_values_with_delimiters(data: list, filepath):
    print("> Testing Mutating Cell Values to Different Delimiters")
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                for delim in delimiters_mutations_arr:
                    d = copy.deepcopy(data)
                    p = get_process(filepath)
                    d[i][j] = delim

                    if send_to_process(p, d, filepath):
                        return True
    return False

def mutate_delimiters(data: list, filepath):
    for delim in delimiters_mutations_arr:
        d = copy.deepcopy(data)
        print(f"Replacing delimiters with {delim}")
        p = get_process(filepath)

        if send_to_process_newdelim(p, d, filepath, delim):
            return True

def flip_bits(data: list, filepath, numflips):
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
                    flipped = uflip_bits(bits)
                    back_to_string = ubits_to_string(flipped)

                    print(f"Bit Flipping (Iter: {num}): {d[i][j]} to {back_to_string}")
                    d[i][j] = back_to_string

                    p = get_process(filepath)
                    if send_to_process(p, d, filepath):
                        return True
    return False


def mutate_strings(data: list, filepath):
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                d = copy.deepcopy(data)
                curr = d[i][j]

                for delim in delimiters_mutations_arr:
                    p = get_process(filepath)
                    rand = replace_random_with_value(curr, delim)
                    print(f"Replacing {i}:{j} with {rand}")
                    d[i][j] = rand
                    if send_to_process(p, d, filepath):
                        return True
    return False

def mutate_index(data: list, filepath):
    print("Sending Payload")
    payload = store.getPay()
    p = get_process(filepath)
    
    p.sendline(payload)
    p.proc.stdin.close()

    TIMEOUT = 1500; 
    startTime = datetime.datetime.now()
    
    code = p.poll(block=True)

    while code is None:
        elapsed = datetime.datetime.now() - startTime
        if (elapsed >= TIMEOUT):
            write_crash_output(filepath, payload)
            print("PROGRAM HUNG")
            break
        code = p.poll(block=True)

    p.close()

    if code != 0:
        write_crash_output(filepath, payload)
        return True
    '''
    Irteza Chaudhry
    Yes, stack smashing is potentially exploitable

    Adam Tanana
    Yes. From stack smashing. Since that's potentially exploitable
    '''
    if code == signal.SIGABRT:
        write_crash_output(filepath, payload)
        return True
    else:
        return False
    

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


'''
attempts to stack smash the binary with %p
'''
def stack_smash(filepath, p_count):

    # Create the payload with %p p_count times in each row, repeated 20 times.
    payload1 = ['header,' + 'must,' + 'stay,' + 'intact']
    payload2 = ['%p'*p_count, '%p'*p_count, '%p'*p_count, '%p'*p_count] * 20
    payload3 = ['%p'*p_count*2, '%p'*p_count*2, '%p'*p_count*2, '%p'*p_count*2]

    # Combine the three payloads
    final_payload = [payload1, payload2, payload3]

    # Print the payload for debugging purposes
    print(f"Payload: {final_payload}")

    # Initialize the process
    p = get_process(filepath)

    #call send_to_process with the payload.

    return False