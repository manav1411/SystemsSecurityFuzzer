from pwn import *
import io
import csv
import copy
import random
import string
from utils import print_crash_found, print_no_crash_found, get_process, write_crash_output

# Number of Total Mutations
NUM_MUTATIONS = 10

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
def list_to_csv(data):
    csv = ''
    for row in data:
        newline = ''
        for ele in row:
            newline += f'{ele},'
        csv += f'{newline[:-1]}\n'
    return csv + '\n'

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(p, csv_payload, filepath):
    payload = list_to_csv(csv_payload)
    p.sendline(payload)
    p.proc.stdin.close()

    code = p.poll(True)

    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

'''
Main function call to begin fuzzing CSV input binaries
'''
def fuzz_csv(filepath, words):
    csv_list = csv_to_list(words)

    for i in range(0, NUM_MUTATIONS):
        deepcopy = copy.deepcopy(csv_list)

        if perform_mutation(filepath, deepcopy, i):
            print_crash_found()
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
    else:
        return False

'''
Adds 1 - 10 New Rows
'''
def add_rows(data: list, filepath):
    print("> Testing Adding Rows")
    d = copy.deepcopy(data)
    rowlen = len(d[0])
    for i in range(1, 11):
        p = get_process(filepath)
        print(f"  > Adding {i} Extra Row(s)")
        
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
    for i in range(1, 11):
        p = get_process(filepath)
        print(f"  > Adding {i} Extra Col(s)")

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
    for i in range(1, 11):
        print(f"  > Adding {i} Extra Cols with {i} Extra Rows")
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