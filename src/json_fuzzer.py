from pwn import *
import json
import copy
from math import pi
from utils import print_crash_found, print_no_crash_found, get_process, write_crash_output, is_num, is_str

# Number of Total Mutations
NUM_MUTATIONS = 5

# Defines for Mutations 
MASS_POS_NUM = 999999999999999999999999999999999999999999999999999999
MASS_NEG_NUM = -999999999999999999999999999999999999999999999999999999
EIGHT_BYTE = 9223372036854775808
MAX_INT_32 = 2147483647
MIN_INT_32 = -2147483648
MAX_INT_64 = 9223372036854775807
MIN_INT_64 = -9223372036854775808

num_mutations_arr = [
    MASS_NEG_NUM, MASS_POS_NUM, EIGHT_BYTE, MAX_INT_32,
    MAX_INT_64, MIN_INT_32, MIN_INT_64, MAX_INT_32 + 1,
    MAX_INT_64 + 1, MIN_INT_32 - 1, MIN_INT_64 - 1, pi
]

queue = []
found_paths = []

'''
Returns whether the given data is valid JSON or not
'''
def is_json(words):
    try:
        json.loads(words)
    except:
        return False
    
    return True

'''
Sends a given input to a process, then returns whether the process crashes or not
> JSON specific <
'''
def send_to_process(p, payload, filepath):
    p.sendline(json.dumps(payload).encode('utf-8')) # back to a string?
    output = p.recvline()

    # A different traversal path has been found and hence it is added to the queue
    if output not in found_paths:
        queue.append(payload) # Add the current payload into the queue
        found_paths.append(output) # Adds the output so we don't encounter it again and keep appending
        print("# == # == # New Path Found # == # == #")

    p.proc.stdin.close()

    code = p.poll(True)
    
    if code != 0:
        write_crash_output(filepath, json.dumps(payload))
        return True
    else:
        return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_json(filepath, words):
    queue.append(json.loads(words))

    # Do the first default payload to see what the intial output should be.
    p = get_process(filepath)
    p.sendline(words)
    output = p.recvline()
    found_paths.append(output)

    for item in queue:
        for i in range(0, NUM_MUTATIONS):
            d = copy.deepcopy(item)
            if perform_mutation(filepath, d, i):
                print_crash_found()
                exit()

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data: json, i):
    if i == 1:
        print("> Testing Sending Nothing")
        if send_to_process(get_process(filepath), '', filepath):
            return True
    elif i == 2:        # Testing Adding Fields
        if (add_fields(data, filepath)):
            return True
    elif i == 3:        # Testing Removing Fields
        if (remove_fields(data, filepath)):
            return True
    elif i == 4:        # Testing Mutating Num Fields
        if (mutate_nums(data, filepath)):
            return True
    else:   
        print("Haven't done this yet!")
        # TODO: Continue Implementing
        return False

'''
Adds 1 - 10 New Fields
'''
def add_fields(data: json, filepath):
    print("> Testing Adding Fields")
    for i in range(1, 11):
        p = get_process(filepath)
        print(f"  > Adding {i} Extra Field(s)")
        d = copy.deepcopy(data)

        for j in range (0, i):
            d[f"RandomField{j}"] = f"RandomValue{j}"
        
        if send_to_process(p, d, filepath):
            return True
        
    return False
        
'''
Removes each of the top level JSON fields
'''
def remove_fields(data: json, filepath):
    print("> Testing Removing Fields")
    keys = data.keys()  
    for i in range(0, len(keys)):
        p = get_process(filepath)
        print(f"  > Removing Field at Index {i}")
        d = copy.deepcopy(data)

        # Ghetto ass solution right now
        # TODO: Pretty sure this only removes top level keys
        j = 0
        for keyValue in keys:
            if j == i: 
                print(f"    > Deleting Field {keyValue}")
                del d[keyValue]
            j += 1
        
        if send_to_process(p, d, filepath):
            return True
        
    return False

'''
Mutates number fields within the JSON to different values
'''
def mutate_nums(data: json, filepath):
    print("> Mutating Number Fields")
    keys = data.keys()

    for keyValue in keys:
        if not is_num(data[keyValue]):
            continue

        for num in num_mutations_arr:
            d = copy.deepcopy(data)
            p = get_process(filepath)
            d[keyValue] = num

            print(f"  > Mutating {keyValue} with {d[keyValue]}")
            if (send_to_process(p, d, filepath)):
                return True

        for i in range(0, 10):
            d = copy.deepcopy(data)
            p = get_process(filepath)
            curr = d[keyValue]

            if i == 0:
                d[keyValue] = int(curr)
            elif i == 1:
                d[keyValue] = curr * 1.0
            elif i == 2:
                d[keyValue] = curr * -1
            elif i == 3:
                d[keyValue] = str(curr)
            else:
                p.proc.stdin.close()
                break

            print(f"  > Mutating {keyValue} with {d[keyValue]}")
            if (send_to_process(p, d, filepath)):
                return True

    return False

# Mutate int inputs with defines
# Mutate string inputs with defines
# Flip Bits
# Swap Types
# Mutate Strings