from pwn import *
import json
import argparse
import subprocess
import sys
import json_fuzzer
import jpeg_fuzzer

context.log_level='warn'

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

# Call this when finding an invalid input
def write_crash_output(filename, input):
    output_file = './fuzzer_output/bad_' + filename[11:] + '.txt'
    with open(output_file, 'w') as file:
        file.write(input)
        file.close()
    print(f"Writing Input: ( {input} ) to Output File : ( {output_file} )")

def get_process(filepath):
    return process(filepath, timeout=1.5)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./fuzzer [binaryname] [sampleinput.txt]")
        exit()

    filepath = './binaries/' + sys.argv[1] # Binary Name
    inputpath = './example_inputs/' + sys.argv[2] # Test Input Name

    # Checks binary file exists
    try:
        with open(filepath, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{filepath}' doesn't exist.{RESET}")
        exit()

    words = []
    # Checks input file exists, extracts sample line-separated input into list
    try:
        with open(inputpath, 'r') as f:
            words = f.read()
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{inputpath}' doesn't exist.{RESET}")
        exit()

    if json_fuzzer.is_json(words):
        print("Found JSON Input > Fuzzing")
        json_fuzzer.fuzz_json(filepath, words)
    
    if jpeg_fuzzer.is_jpeg(words):
        print("Found JPEG Input > Fuzzing")
        jpeg_fuzzer.fuzz_jpeg(filepath, words)

    # Other filetype checks
    print("Not a JSON File")
