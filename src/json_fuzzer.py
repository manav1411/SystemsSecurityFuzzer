import json
import copy
from pwn import *
from fuzzer import write_crash_output, get_process

# Number of Total Mutations
NUM_MUTATIONS = 3

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

def send_to_process(p, payload, filepath):
    p.sendline(json.dumps(payload).encode('utf-8')) # back to a string?
    p.proc.stdin.close()

    code = p.poll(True)
    
    # TODO: I'm not sure if this is the right check or not
    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False
    
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
        deepcopy = copy.deepcopy(data)
        if perform_mutation(filepath, deepcopy, i):
            exit()

    print("################################")
    print("### No Crashable Input Found ###")
    print("################################")
    exit()

def perform_mutation(filepath, data: json, i):
    if i == 0:          # Default Payload Test
        print("> Testing Normal Payload")
        send_to_process(get_process(filepath), data, filepath)
    elif i == 1:
        print("> Testing Sending Nothing")
        send_to_process(get_process(filepath), '', filepath)
    elif i == 2:        # Testing Adding Fields
        if (add_fields(data, filepath)):
            return True
    elif i == 3:        # Testing Removing Fields
        if (remove_fields(data, filepath)):
            return True
    elif i == 4:
        print("Haven't done this yet!")
        # TODO: Continue Implementing

    return False

def add_fields(data: json, filepath):
    for i in range(1, 11):
        p = get_process(filepath)
        print(f"> Adding {i} Extra Field(s)")
        deepcopy = copy.deepcopy(data)

        for j in range (0, i):
            deepcopy[f"RandomField{j}"] = f"RandomValue{j}"
        
        if send_to_process(p, deepcopy, filepath):
            return True
        
    return False
        

def remove_fields(data: json, filepath):
    keys = data.keys()  
    for i in range(0, len(keys)):
        p = get_process(filepath)
        print(f"> Removing Field at Index {i}")
        deepcopy = copy.deepcopy(data)

        # Ghetto ass solution right now
        # TODO: Pretty sure this only removes top level keys
        j = 0
        for keyValue in keys:
            if j == i: 
                print(f"    Deleting Field {keyValue}")
                del deepcopy[keyValue]
            j += 1
        
        if send_to_process(p, deepcopy, filepath):
            return True
        
    return False

# Mutate int inputs with defines
# Mutate string inputs with defines
# Flip Bits
# Swap Types
# Mutate Strings