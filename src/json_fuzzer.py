import json
from pwn import *
from fuzzer import write_crash_output

# Number of Total Mutations
NUM_MUTATIONS = 10

# Hardcoded Values for Initial Mutation of Input
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

# Returns whether the given data is valid JSON or not
def is_json(words):
    try:
        json.loads(words)
    except:
        return False
    
    return True

# 
'''
    Main call when fuzzing JSON
    The second strategy is to concentrate on finding bugs after the document has been parsed/processed. In this case 
    we will aim to submit unexpected input but still stick to the format and the specifications of the document. This 
    strategy is used to discover a lot wider range of bugs depending on how the structured data is used later on inside 
    the application. The types of bugs discovered will depend on the targeted platform, language and all kinds of other 
    things.

    (MIN_INT, MAX_INT, UNSIGNED MAX_INT, LONG, etc). Unexpected input is also logical values such as true and false, 
    the special atom nil, null and 0 and 1.

    Try sending some known sample inputs (nothing, certain numbers, certain strings, etc)
    Try parsing the format of the input (normal text, json, etc) and send correctly formatted data with fuzzed fields.
    Try manipulating the sample input (bit flips, number replacement, etc)
'''
def fuzz_json(filepath, words):
    data = json.loads(words)

    # Endlessly loop through mutations
    for i in range(0, NUM_MUTATIONS):
        if perform_mutation(filepath, data, i):
            exit()

    print("No Crashable Input Found")
    exit()

def perform_mutation(filepath, data: json, i):
    payload = ''

    if i == 0:                  # Default Payload Test
        payload = data
    elif i < 0 and i < 10:      # Testing Adding Fields
        payload = add_fields(data, i)

    p = process(filepath, timeout=1.5)
    p.sendline(json.dumps(payload).encode('utf-8')) # back to a string?
    p.proc.stdin.close()

    code = p.poll(True)
    
    # TODO: I'm not sure if this is the right check or not
    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

def add_fields(data: json, numfields):
    jsonData = json.load(data)
    for i in range(numfields):
        jsonData[f"RandomField{i}"] = f"RandomValue{i}"

    return jsonData
        

def remove_fields(data):
    return 0

def send_nothing(data):
    return 0