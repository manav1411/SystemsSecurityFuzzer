from pwn import *
import io
import csv
import copy
from utils import print_crash_found, print_no_crash_found, get_process, write_crash_output

# Number of Total Mutations
NUM_MUTATIONS = 3

# taken from json_fuzzer.py, but not used
MASS_POS_NUM = 999999999999999999999999999999999999999999999999999999
MASS_NEG_NUM = -999999999999999999999999999999999999999999999999999999
OVERFLOW = "A" * 10000
BOUNDARY_MINUS = -1
BOUNDARY_PLUS = 1
ZERO = 0
ONE_BYTE = 128
TWO_BYTE = 32768
FOUR_BYTE = 2147483648
EIGHT_BYTE = 9223372036854775808
FORMAT = "%p"


def is_csv(words):
    try:
        csv.reader(words)
    except:
        return False
    return True

def csv_to_string(words):
    output = io.StringIO()
    writer = csv.writer(output)

    reader = csv.reader(words)

    for row in reader:
        writer.writerow(row)

    csv_string = output.getvalue()
    output.close()
    return csv_string

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(p, csv_payload, filepath):
    payload = csv_to_string(csv_payload)
    p.sendline(csv_to_string(payload).encode('utf-8'))
    p.proc.stdin.close()

    code = p.poll(True)

    if code != 0:
        write_crash_output(filepath, payload)
        return True
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


'''
Begins the mutation process with a range of CSV files
'''
def perform_mutation(filepath, data, i):
    if i == 0:          # Default Payload Test
        print("> Testing Normal Payload")
        return send_to_process(get_process(filepath), data, filepath)
    elif i == 1:
        print("> Testing Empty Payload")
        return send_to_process(get_process(filepath), "", filepath)
    elif i == 2:
        return add_extra_comma(data, filepath)
    else:
        return False


'''
Main function call to begin fuzzing CSV input binaries
'''
def fuzz_csv(filepath, words):
    csv_string = csv_to_string(words)

    for i in range(0, NUM_MUTATIONS):
        deepcopy = copy.deepcopy(csv_string)

        if perform_mutation(filepath, deepcopy, i):
            print_crash_found()
            exit()

    print_no_crash_found()