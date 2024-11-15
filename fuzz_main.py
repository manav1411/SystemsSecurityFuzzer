import fuzz_json
import fuzz_csv
import fuzz_jpeg
import fuzz_plaintext
import fuzz_xml
import fuzz_pdf
import fuzz_elf
import os

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

def fuzz(file, input):
    print(f"Fuzzing Binary: {file}")
    filepath = './binaries/' + file # Binary Name
    inputpath = './example_inputs/' + input # Test Input Name
    if os.path.isfile('./log.txt'):
        os.remove('./logs.txt')

    # Checks binary file exists
    try:
        with open(filepath, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{filepath}' doesn't exist.{RESET}")
        return

    # Checks input file exists, extracts sample line-separated input into list
    try:
        with open(inputpath, 'rb') as f:
            words = f.read()
    except FileNotFoundError:
        print(f"{RED}ERROR 404: the file '{inputpath}' doesn't exist.{RESET}")
        return

    if fuzz_json.is_json(words):
        print("Found JSON Input > Fuzzing")
        fuzz_json.fuzz_json(filepath, words)
    elif fuzz_elf.is_elf(filepath):
        print("Found ELF Input > Fuzzing")
        fuzz_elf.fuzz_elf(filepath, words)
    elif fuzz_jpeg.is_jpeg(words):
        print("Found JPEG Input > Fuzzing")
        fuzz_jpeg.fuzz_jpeg(filepath, words)
    elif fuzz_xml.is_xml(inputpath):
        print("Found XML Input  > Fuzzing")
        fuzz_xml.fuzz_xml(filepath, inputpath)
    elif fuzz_csv.is_csv(words.decode("utf-8")):
        print("Found CSV Input  > Fuzzing")
        fuzz_csv.fuzz_csv(filepath, words.decode("utf-8"))
    elif fuzz_pdf.is_pdf(words.decode("utf-8")):
        print("Found pdf Input  > Fuzzing")
        fuzz_pdf.fuzz_pdf(filepath, words.decode("utf-8"))
    else:
        print("No Input Type Detected, Assuming Plaintext Input > Fuzzing")
        fuzz_plaintext.fuzz_plaintext(filepath, words)