import argparse
import subprocess

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

def valid_input_test(file, words):
    for word in words:
        try:
            # Run file, pass it given word, capture output.
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

    except Exception as e:
        print(f"{RED}[ERROR] An error occurred: {e}{RESET}")



if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description='Multithreaded file runner.')
    parser.add_argument('-f', '--file', type=str, required=True, help='binary to run')
    parser.add_argument('-i', '--input', type=str, required=True, help='line-separated valid inputs for binary')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads (ignored for now)')
    args = parser.parse_args()

    # Checks binary file exists
    try:
        with open(args.file, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{args.file}' doesn't exist.{RESET}")
        exit()

    words = []
    # Checks input file exists, extracts sample line-separated input into list
    try:
        with open(args.input, 'r') as f:
            words = f.readlines()
            words = [word.strip() for word in words]
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{args.input}' doesn't exist.{RESET}")
        exit()


    # runs binary with the list of words
    valid_input_test(args.file, words)
    long_input_test(args.file)
