from pwn import *
import io
import csv
import copy
import random
import string
import signal
import datetime
from math import pi
from utils import *

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

'''
Switch to True if you want to see the inputs / outputs being send to / received from the binary
'''
SEE_INPUTS = True
PRINT_OUTPUTS = True


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

queue = []
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
    if SEE_INPUTS:
        print(payload)
    p.sendline(payload)

    try: 
        output = p.recvline()
        if PRINT_OUTPUTS:
            print(f"Output: {output}")
        # A different traversal path has been found and hence it is added to the queue
        elif output not in found_paths:
            # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
            if not ("invalid" in output or "Invalid" in output):
                queue.append(csv_payload) # Add the current payload into the queue
                found_paths.append(output) # Adds the output so we don't encounter it again and keep appending
                print_new_path_found()
    except:
        pass

    p.proc.stdin.close()

    code = p.poll(True)
    
    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

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
def fuzz_csv(filepath, words):
    queue.append(csv_to_list(words))

    # Do the first default payload to see what the intial output should be.
    p = get_process(filepath)
    p.sendline(words)
    output = p.recvline()
    found_paths.append(output)

    for item in queue:
        for i in range(0, NUM_MUTATIONS):
            deepcopy = copy.deepcopy(item)

            if perform_mutation(filepath, deepcopy, i):
                print_crash_found()
                exit()

    print_no_crash_found()

'''
Begins the mutation process with a range of CSV files
'''
def perform_mutation(filepath, data, i):
    if i == 0:
        pass # clean up later
    elif i == 1:
        pass # clean up later
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
    elif i == 10:
        if mutate_index(data, filepath):
            return True
    elif i == 11:
        if mutate_strings(data, filepath):
            return True
    elif i == 12:
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
    print("Mutating delimiters")
    for delim in delimiters_mutations_arr:
        d = copy.deepcopy(data)
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
                    d[i][j] = rand
                    if send_to_process(p, d, filepath):
                        return True
    return False

def mutate_index(data: list, filepath):
    print("Mutating indexes with string of len 0 - 100")
    width = len(data[0])
    height = len(data)

    for i in range(0, height):
            for j in range (0, width):
                d = copy.deepcopy(data)
                for x in range (0, 1000):
                    p = get_process(filepath)
                    d[i][j] = 'A' * x
                    if send_to_process(p, d, filepath):
                        return True
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

    return False