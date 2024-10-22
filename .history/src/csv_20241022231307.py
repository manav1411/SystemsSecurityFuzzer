from pwn import *
import csv

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


def fuzz_csv(filepath, words):
    data = csv.reader(words)
    p = get_process()

    for i in range(NUM_MUTATIONS):
        payload = copy.deepcopy(data)

        # Mutate the data
        payload[0] = MASS_POS_NUM
        payload[1] = MASS_NEG_NUM
        payload[2] = OVERFLOW
        payload[3] = BOUNDARY_MINUS
        payload[4] = BOUNDARY_PLUS
        payload[5] = ZERO
        payload[6] = ONE_BYTE
        payload[7] = TWO_BYTE
        payload[8] = FOUR_BYTE
        payload[9] = EIGHT_BYTE
        payload[10] = FORMAT

        if send_to_process(p, payload, filepath):
            return True

    return False