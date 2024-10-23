import json
import copy
from math import pi
from pwn import *
from fuzzer import write_crash_output, get_process

# Number of Total Mutations
NUM_MUTATIONS = 5

# Hardcoded Values for Initial Mutation of Input
MASS_POS_NUM = 999999999999999999999999999999999999999999999999999999
MASS_NEG_NUM = -999999999999999999999999999999999999999999999999999999
EIGHT_BYTE = 9223372036854775808
MAX_INT_32 = 2147483647
MIN_INT_32 = -2147483648
MAX_INT_64 = 9223372036854775807
MIN_INT_64 = -9223372036854775808

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
Checks whether a given data is an int
'''
def is_num(data):
    return isinstance(data, int)

'''
Checks whether a given data is a str
'''
def is_str(data):
    return isinstance(data, str)

'''
Sends a given input to a process, then returns whether the process crashes or not
> JSON specific <
'''
def send_to_process(p, payload, filepath):
    p.sendline(json.dumps(payload).encode('utf-8')) # back to a string?
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
    data = json.loads(words)

    # Endlessly loop through mutations
    for i in range(0, NUM_MUTATIONS):
        d = copy.deepcopy(data)
        if perform_mutation(filepath, d, i):
            print("#########################################")
            print("######### Crashable Input Found #########")
            print("#########################################")
            exit()

    print("########################################")
    print("####### No Crashable Input Found #######")
    print("########################################")

'''
Begins the mutation process
'''
def perform_mutation(filepath, data: json, i):
    if i == 0:          # Testing Default Payload
        print("> Testing Normal Payload")
        send_to_process(get_process(filepath), data, filepath)
    elif i == 1:        # Testing Nothing Payload
        print("> Testing Sending Nothing")
        send_to_process(get_process(filepath), '', filepath)
    elif i == 2:        # Testing Adding Fields
        if (add_fields(data, filepath)):
            return True
    elif i == 3:        # Testing Removing Fields
        if (remove_fields(data, filepath)):
            return True
    elif i == 4:        # Testing Mutating Num Fields
        if (mutate_nums(data, filepath)):
            return True
    elif i == 5:
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
    d = copy.deepcopy(data)

    for keyValue in keys:
        if not is_num(d[keyValue]):
            continue

        for i in range(0, 100):
            p = get_process(filepath)
            curr = d[keyValue]

            if i == 0:
                d[keyValue] = int(curr)
            elif i == 1:
                d[keyValue] = MAX_INT_32
            elif i == 2:
                d[keyValue] = MIN_INT_32
            elif i == 3:
                d[keyValue] = MAX_INT_64
            elif i == 4:
                d[keyValue] = MIN_INT_64
            elif i == 5:
                d[keyValue] = MAX_INT_32 + 1
            elif i == 6:
                d[keyValue] = MIN_INT_32 - 1
            elif i == 7:
                d[keyValue] = MAX_INT_64 + 1
            elif i == 8:
                d[keyValue] = MIN_INT_64 - 1
            elif i == 9:
                d[keyValue] = pi
            elif i == 10:
                d[keyValue] = curr * 1.0
            elif i == 11:
                d[keyValue] = curr * -1
            elif i == 12:
                d[keyValue] = str(curr)
            elif i == 13:
                d[keyValue] = MASS_POS_NUM
            elif i == 14:
                d[keyValue] = MASS_NEG_NUM
            else:
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