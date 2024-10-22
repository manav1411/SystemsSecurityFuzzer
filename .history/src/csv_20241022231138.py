import csv
from pwn import *

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
        json.loads(words)
    except:
        return False

    return True

data = [
    {'name': 'Nikhil', 'branch': 'COE', 'year': 2, 'cgpa': 9.0},
    {'name': 'Sanchit', 'branch': 'COE', 'year': 2, 'cgpa': 9.1},
    {'name': 'Aditya', 'branch': 'IT', 'year': 2, 'cgpa': 9.3},
    {'name': 'Sagar', 'branch': 'SE', 'year': 1, 'cgpa': 9.5},
    {'name': 'Prateek', 'branch': 'MCE', 'year': 3, 'cgpa': 7.8},
    {'name': 'Sahil', 'branch': 'EP', 'year': 2, 'cgpa': 9.1}
]

with open('university_records.csv', 'w', newline='') as csvfile:
    fieldnames = ['name', 'branch', 'year', 'cgpa']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(data)