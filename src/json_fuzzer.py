import json
import copy
import time
from math import pi
from utils import *
import subprocess

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = False
PRINT_OUTPUTS = False

arr_of_types = ["A" * 400, -1389054671389658013709571389065891365890189164, json.loads('{"Name": "Jennifer Smith"}'), ["A", 1234, "Meow", -9999], None, True, False]
type_swaps_arr = ["A" * 2000, -9999999999999999999999999999999999999999999999999999999999999999999, json.loads('{"Name": "Jennifer Smith","Contact Number": 7867567898,"Email": "jen123@gmail.com","Hobbies":["Reading", "Sketching", "Horse Riding"]}'), arr_of_types, None, True, False]

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
'''
def send_to_process(payload, filepath):
    payload = json.dumps(payload)
    if SEE_INPUTS:
        print(payload)
    
    try:
        process = subprocess.run(
            [filepath],
            input=payload,
            text=True,
            capture_output=True
        )
        
        # Capture the return code and output
        code = process.returncode
        output = process.stdout

        if PRINT_OUTPUTS:
            print(output)
        
    except Exception as e:
        print(e)
        return False
    
    if output == "":
        pass
    # A different traversal path has been found and hence it is added to the queue
    elif output not in found_paths:
        # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
        if not ("invalid" in output or "Invalid" in output):
            # Add the current payload into the queue
            queue.append(json.loads(payload))

            # Adds the output so we don't encounter it again and keep appending 
            found_paths.append(output)
            print_new_path_found()
            time.sleep(1)
    
    if code != 0:
        write_crash_output(filepath, json.dumps(payload))
        return True
    else:
        return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_json(filepath, words):
    words = json.loads(words.decode("utf-8"))

    send_to_process(words, filepath)

    for item in queue:
        print(queue)
        print(found_paths)
        d = copy.deepcopy(item)
        if perform_mutation(filepath, d):
            print_crash_found()
            exit()

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data: json):
    if send_to_process('', filepath): return True
    if add_fields(data, filepath): return True
    if remove_fields(data, filepath): return True
    if mutate_nums(data, filepath): return True
    if mutate_strings(data, filepath): return True
    if flip_bits(data, filepath): return True
    if swap_types(data, filepath): return True
    return False

'''
Adds 1 - 10 New Fields
'''
def add_fields(data: json, filepath):
    print("> Testing Adding Fields")
    for i in range(1, 11):
        
        print(f"  > Adding {i} Extra Field(s)")
        d = copy.deepcopy(data)

        for j in range (0, i):
            d[f"RandomField{j}"] = f"RandomValue{j}"
        
        if send_to_process(d, filepath):
            return True
        
    return False
        
'''
Removes each of the top level JSON fields
'''
def remove_fields(data: json, filepath):
    print("> Testing Removing Fields")
    keys = data.keys()  
    for keyValue in keys:
        
        d = copy.deepcopy(data)
        print(f"    > Deleting Field {keyValue}")
        del d[keyValue]

        if send_to_process(d, filepath):
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

        with open('./src/wordlists/allnumber.txt', 'r') as file:
            for line in file:
                d = copy.deepcopy(data)
                
                d[keyValue] = line
                
                if (send_to_process(d, filepath)):
                    file.close()
                    return True
            file.close()
    return False

'''
Mutates string fields within the JSON to different values
'''
def mutate_strings(data: json, filepath):
    print("> Mutating String Fields")
    keys = data.keys()

    for keyValue in keys:
        if not is_str(data[keyValue]):
            continue

        with open('./src/wordlists/naughtystrings.txt', 'r') as file:
            for line in file:
                d = copy.deepcopy(data)
                
                d[keyValue] = line
                
                if (send_to_process(d, filepath)):
                    file.close()
                    return True
            file.close()
    return False

'''
Mutates fields with the bits randomly flipped
'''
def flip_bits(data: json, filepath):
    print("> Flipping Bits")
    keys = data.keys()

    for keyValue in keys:
        for i in range(0, 100):
            d = copy.deepcopy(data)
            
            if is_num(d[keyValue]):
                d[keyValue] = ubits_to_number(uflip_bits(unumber_to_bits(d[keyValue])))
            elif is_str(d[keyValue]):
                d[keyValue] = ubits_to_string(uflip_bits(ustring_to_bits(d[keyValue])))

            if (send_to_process(d, filepath)):
                return True
            
    return False

'''
Swap the types of JSON Fields to other types
'''
def swap_types(data: json, filepath):
    print("Swapping types of JSON Fields")
    keys = data.keys()

    for keyValue in keys:
        for type in type_swaps_arr:
            d = copy.deepcopy(data)
            

            d[keyValue] = type

            if (send_to_process(d, filepath)):
                return True
    return False
