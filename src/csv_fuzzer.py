from pwn import *
import csv

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


def run_binary_with_csv(binary_path, csv_file):
    try:
        result = subprocess.run([binary_path, csv_file], check=True, capture_output=True, text=True)
        print(f"Binary output for {csv_file}:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error running binary for {csv_file}:\n{e.stderr}")


def fuzz_binary(iterations, fuzz_dir):
    for i in range(iterations):
        # Either generate valid or malformed CSV
        csv_file_path = os.path.join(fuzz_dir, f'fuzz_input_{i}.csv')

        if random.random() < 0.5:
            generate_random_csv(csv_file_path)
        else:
            generate_malformed_csv(csv_file_path)

        run_binary_with_csv(csv_file_path)