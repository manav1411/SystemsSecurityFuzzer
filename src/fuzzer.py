from pwn import *
import sys
import json_fuzzer
import csv_fuzzer
import jpeg_fuzzer

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 src/fuzzer.py [binaryname] [sampleinput.txt]")
        exit()

    print(f"Running Binary: {sys.argv[1]}")

    filepath = './binaries/' + sys.argv[1] # Binary Name
    inputpath = './example_inputs/' + sys.argv[2] # Test Input Name

    # Checks binary file exists
    try:
        with open(filepath, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{filepath}' doesn't exist.{RESET}")
        exit()

    # Checks input file exists, extracts sample line-separated input into list
    try:
        with open(inputpath, 'rb') as f:
            words = f.read()
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{inputpath}' doesn't exist.{RESET}")
        exit()

    if json_fuzzer.is_json(words):
        print("Found JSON Input > Fuzzing")
        json_fuzzer.fuzz_json(filepath, words)
        exit()
    
    if jpeg_fuzzer.is_jpeg(words):
        print("Found JPEG Input > Fuzzing")
        jpeg_fuzzer.fuzz_jpeg(filepath, words)
        exit()

    if csv_fuzzer.is_csv(words):
        print("Found CSV Input  > Fuzzing")
        csv_fuzzer.fuzz_csv(filepath, words)
        exit()

    # Other filetype checks
    print("No current supported fuzzing input has been detected!")
