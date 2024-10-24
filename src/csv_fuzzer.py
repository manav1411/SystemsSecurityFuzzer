from pwn import *
import io
import csv
import copy
from fuzzer import write_crash_output, get_process

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

def csv_to_string(csv_filepath):
    output = io.StringIO()

    with open(csv_filepath, 'r') as csvfile:
        reader = csv.reader(csvfile)

        writer = csv.writer(output)
        for row in reader:
            writer.writerow(row)

    csv_string = output.getvalue()
    output.close()
    return csv_string

def send_csv_to_process(p, payload, filepath):
    payload = csv_to_string(payload)
    p.sendline(csv_to_string(payload).encode('utf-8'))
    p.proc.stdin.close()

    code = p.poll(True)

    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

def fuzz_csv(filepath, words):
    csv_string = csv_to_string(words)

    for i in range(0, NUM_MUTATIONS):
        deepcopy = copy.deepcopy(csv_string)
        if perform_mutation(filepath, deepcopy, i):
            exit()

def perform_mutation(filepath, data, i):
    if i == 0:          # Default Payload Test
        print("> Mutation Case 1")
    elif i == 1:
        print("> Mutation Case 2")
    elif i == 2:
        print("Haven't done this yet!")
        # TODO: Continue Implementing
    else:
        return False

    return False

def generate_random_csv(file_path, max_rows=10, max_columns=5):
    rows = random.randint(1, max_rows)
    columns = random.randint(1, max_columns)

    with open(file_path, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        for _ in range(rows):
            row_data = [''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 10)))
                        for _ in range(columns)]
            csvwriter.writerow(row_data)


def generate_malformed_csv(file_path, max_rows=10, max_columns=5):
    rows = random.randint(1, max_rows)
    columns = random.randint(1, max_columns)

    with open(file_path, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        for _ in range(rows):
            # Omit cols randomly
            if random.random() < 0.5:
                columns_in_row = random.randint(1, columns)
            else:
                columns_in_row = columns

            row_data = [''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 10))) for _ in range(columns_in_row)]

            if random.random() < 0.3:  # Add random extra commas or other invalid CSV syntax
                row_data[random.randint(0, len(row_data) - 1)] += ',' * random.randint(1, 5)

            # TODO: Add more malformed CSV cases
            # e.g. integer overflow, underflow, negative numbers, etc.

            csvwriter.writerow(row_data)
