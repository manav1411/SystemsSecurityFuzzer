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
    # TODO: Implement CSV Fuzzer
    pass