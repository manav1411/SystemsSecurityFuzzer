import argparse
import subprocess
import sys
import json_fuzzer

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

'''
https://en.wikipedia.org/wiki/American_Fuzzy_Lop_(software)
'''

def valid_input_test(file, words):
    for word in words:
        try:
            # Run file, pass it given word, capture output.
            print(file)
            process = subprocess.Popen([f"./{file}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = process.communicate(input=word)

            # Print program output
            if output:
                print(f"{GREEN}'{word}'{RESET}: {output.strip()}")

            # Case program exited with a non-0 return code
            return_code = process.returncode
            if return_code != 0:
                print(f"{RED}[ERROR]{RESET} exit code: {return_code}, for {YELLOW}'{word}'{RESET}: {error.strip()}")

        except Exception as e:
            print(f"{RED}[ERROR] An error occurred: {e}{RESET}")


def long_input_test(file):
    long_input = 'A' * 100
    try:
        # Run file, pass it the long input, capture output.
        process = subprocess.Popen([f"./{file}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate(input=long_input)

        # Print program output
        if output:
            print(f"{YELLOW}'{long_input}'{RESET}: {output.strip()}")

        # Check if the program exited with a non-0 return code
        return_code = process.returncode
        if return_code != 0:
            print(f"{RED}[ERROR]{RESET} exit code: {return_code}, for {YELLOW}'{long_input}'{RESET}: {error.strip()}")
            write_crash_output(file, long_input)

    except Exception as e:
        print(f"{RED}[ERROR] An error occurred: {e}{RESET}")

# Call this when finding an invalid input
def write_crash_output(filename, input):
    output_file = './fuzzer_output/bad_' + filename[11:] + '.txt'
    with open(output_file, 'w') as file:
        file.write(input)
        file.close()
    print(f"Writing Input: ( {input} ) to Output File : ( {output_file} )")

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

    # Other filetype checks
    print("NOT JSON")
