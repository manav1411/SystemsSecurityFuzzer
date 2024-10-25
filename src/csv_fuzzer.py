from pwn import *
import io
import csv
import copy
from utils import print_crash_found, print_no_crash_found, get_process, write_crash_output

# Number of Total Mutations
NUM_MUTATIONS = 3

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
    payload = ''
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
    print(words)
    csv_list = csv_to_list(words)
    print(csv_list)
    csv_back_to_csv = list_to_csv(csv_list)
    print(csv_back_to_csv)

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
        return send_to_process(get_process(filepath), data, filepath)
    elif i == 1:
        print("> Testing Empty Payload")
        return send_to_process(get_process(filepath), "", filepath)
    elif i == 2:
        return add_extra_comma(data, filepath)
    else:
        return False


def add_extra_comma(data: csv, filepath):
    print("> Testing Adding Comma")
    for i in range(1, 11):
        p = get_process(filepath)
        print(f"  > Adding {i} Extra Field(s)")
        d = copy.deepcopy(data)

        csv_output = io.StringIO()
        csvwriter = csv.writer(csv_output)

        # Write all original data to the new CSV output
        for row in d:
            csvwriter.writerow(row)

        new_row = [str(i)] * i  # Creates a row like ['1', '1', ..., '1']
        new_row.extend([","] * i)  # Add 3 extra commas (i.e. empty fields)
        csvwriter.writerow(new_row)  # Write the new row to the CSV

        csv_output.close()

        if send_to_process(p, d, filepath):
            return True

    return False