import io
import csv
import copy
import random
import string
import subprocess
import time
import threading
from math import pi
from utils import *

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

'''
Switch to True if you want to see the inputs / outputs being send to / received from the binary
'''
SEE_INPUTS = False
PRINT_OUTPUTS = False


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
def send_to_process(csv_payload, filepath):
    payload = list_to_csv(csv_payload, ',')
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
            print(" >> New Path Found, Adding to Queue")
            print(payload)
            
            # Add the current payload into the queue
            queue.append(csv_to_list(payload))

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
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process_newdelim(csv_payload, filepath, delimiter):
    payload = list_to_csv(csv_payload, delimiter)
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
            print(" >> New Path Found, Adding to Queue")
            print(payload)
            # Add the current payload into the queue
            queue.append(csv_to_list(payload))

            # Adds the output so we don't encounter it again and keep appending 
            found_paths.append(output)
            print_new_path_found()
            time.sleep(1)
    
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
Main function call to begin fuzzing CSV input binaries
'''
def fuzz_csv(filepath, words):
    global start
    start = time.time()
    queue.append(csv_to_list(words))

    # Do the first default payload to see what the intial output should be.
    send_to_process(words, filepath)

    for item in queue:
        d = copy.deepcopy(item)
        if perform_mutation(filepath, d):
            return

    print_no_crash_found()

'''
Begins the mutation process with a range of CSV files
'''
def perform_mutation(filepath, data):
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
Adds 1 - 100 New Rows
'''
def add_rows(data: list, filepath):
    global crashed
    print("> Testing Adding Rows")
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
    print("- Finished Adding Rows")

'''
Adds 1 - 100 New Cols
'''
def add_cols(data: list, filepath):
    global crashed
    print("> Testing Adding Columns")
    d = copy.deepcopy(data)
    for i in range(1, 101):
        
        for row in d:
            row.append(random.choice(string.ascii_letters))

        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return
    print("- Finished Adding Cols")

'''
Adds both extra rows and columns at the same time
'''
def add_cols_and_rows(data: list, filepath):
    global crashed
    print("> Testing Adding Rows and Columns")
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
    print("- Finished Adding Rows and Cols")

'''
Changes every cell in the CSV to all defined num values
'''
def mutate_data_ints(data: list, filepath):
    global crashed
    print("> Testing Mutating Cell Values to Different Numbers")
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
    print("- Finished Mutating Nums")
    return

'''
Changes every cell in the CSV to all defined delimiter values
'''
def mutate_data_values_with_delimiters(data: list, filepath):
    global crashed
    print("> Testing Mutating Cell Values to Different Delimiters")
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
    print("- Finished Mutatating with Delimiters")
                    
'''
Mutates the delimiters for the CSV File
'''
def mutate_delimiters(data: list, filepath):
    global crashed
    print("> Mutating delimiters")
    for delim in delimiters_mutations_arr:
        d = copy.deepcopy(data)
        
        if crashed: return
        if send_to_process_newdelim(d, filepath, delim):
            crashed = True
            return
    print("- Finished Changing Delimiters")

'''
Flips bits of the values contained within the CSV
'''
def flip_bits(data: list, filepath, numflips):
    global crashed
    print("> Flipping Bits")
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

                    
                    if crashed: return
                    if send_to_process(d, filepath):
                        crashed = True
                        return
    print("- Finished Flipping Bits")

'''
Mutates the strings within the CSV
'''
def mutate_strings(data: list, filepath):
    global crashed
    print("> Mutating Strings")
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
    print("- Finished Mutating Strings")
    return

'''
Tries to add 1 - 1000 length strings in each index of the CSV
'''
def mutate_index(data: list, filepath, startNum):
    global crashed
    print(f"> Mutating indexes with string of len {startNum} - {startNum + 500}")
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
    print(f"- Finished Mutating indexes with string of len {startNum} - {startNum + 500}")
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
