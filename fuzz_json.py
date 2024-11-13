import json
import copy
import time
import signal
from utils import *
import subprocess
import threading

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = False 
PRINT_OUTPUTS = False

'''
Mutations defines
'''
arr_of_types = ["A" * 400, -1389054671389658013709571389065891365890189164, json.loads('{"Name": "Jennifer Smith"}'), ["A", 1234, "Meow", -9999], None, True, False]
type_swaps_arr = ["A" * 2000, -9999999999999999999999999999999999999999999999999999999999999999999, json.loads('{"Name": "Jennifer Smith","Contact Number": 7867567898,"Email": "jen123@gmail.com","Hobbies":["Reading", "Sketching", "Horse Riding"]}'), arr_of_types, None, True, False]

'''
Queueing for code coverage
'''
queue = []
found_paths = []

'''
Timing Things
'''
start = 0
end = 0

'''
Threads for multithreading
'''
crashed = False
threads = []

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
            print(" >> New Path Found, Adding to Queue")
            print(payload)
            
            # Add the current payload into the queue
            queue.append(json.loads(payload))

            # Adds the output so we don't encounter it again and keep appending 
            found_paths.append(output)
    
    if code != 0:
        global crashed
        crashed = True
        end = time.time()
        write_crash_output(filepath, json.dumps(payload))
        progress_bar(1, 1)
        print_crash_found()
        print_some_facts(len(found_paths), end - start, get_signal(code))
        return True
    else:
        return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_json(filepath, words):
    global start
    start = time.time()
    words = json.loads(words)

    send_to_process(words, filepath)

    for item in queue:
        d = copy.deepcopy(item)
        if perform_mutation(filepath, d):
            return

    print_no_crash_found()

'''
Begins the mutation process
'''
def perform_mutation(filepath, data: json):
    global crashed
    threads.append(threading.Thread(target=add_fields, args=(data, filepath)))
    threads.append(threading.Thread(target=remove_fields, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_nums, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_strings, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits, args=(data, filepath)))
    threads.append(threading.Thread(target=swap_types, args=(data, filepath)))
    
    while len(threads) > 0:
        t = threads.pop()
        t.start()

    print_line()
    numthreads = (threading.active_count() - 1) # We subtract the main thread
    workingThreads = 1

    while workingThreads:
        workingThreads = threading.active_count() - 1
        progress_bar(numthreads - workingThreads, numthreads)
        if crashed: 
            return True
    return False

'''
Adds 1 - 1000 New Fields
'''
def add_fields(data: json, filepath):
    global crashed
    print("> Testing Adding Fields")
    for i in range(1,1001):
        d = copy.deepcopy(data)

        for j in range (0, i):
            d[f"RandomField{j}"] = f"RandomValue{j}"
        
        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return
    print("- Finished Adding Fields")
        
'''
Removes each of the top level JSON fields
'''
def remove_fields(data: json, filepath):
    global crashed
    print("> Testing Removing Fields")
    keys = data.keys()  
    for keyValue in keys:
        d = copy.deepcopy(data)
        del d[keyValue]
        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return
    print("- Finished Removing Fields")

'''
Mutates number fields within the JSON to different values
'''
def mutate_nums(data: json, filepath):
    print("> Mutating Number Fields")
    global crashed
    keys = data.keys()

    for keyValue in keys:
        if not is_num(data[keyValue]):
            continue

        with open('./wordlists/allnumber.txt', 'r') as file:
            for line in file:
                d = copy.deepcopy(data)
                
                d[keyValue] = line

                if crashed: 
                    file.close()
                    return
                if (send_to_process(d, filepath)):
                    file.close()
                    crashed = True
                    return
            file.close()
    print("- Mutating Numbers")

'''
Mutates string fields within the JSON to different values
'''
def mutate_strings(data: json, filepath):
    global crashed
    print("> Mutating String Fields")
    keys = data.keys()

    for keyValue in keys:
        if not is_str(data[keyValue]):
            continue

        with open('./wordlists/naughtystrings.txt', 'r') as file:
            for line in file:
                d = copy.deepcopy(data)
                
                d[keyValue] = line
                
                if crashed:
                    file.close()
                    return
                if send_to_process(d, filepath):
                    crashed = True
                    return
            file.close()
    print("- Finished Mutating Strings")

'''
Mutates fields with the bits randomly flipped
'''
def flip_bits(data: json, filepath):
    global crashed
    print("> Flipping Bits")
    keys = data.keys()

    for keyValue in keys:
        for i in range(0, 100):
            d = copy.deepcopy(data)

            if is_num(d[keyValue]):
                d[keyValue] = ubits_to_number(uflip_bits(unumber_to_bits(d[keyValue])))
            elif is_str(d[keyValue]):
                d[keyValue] = ubits_to_string(uflip_bits(ustring_to_bits(d[keyValue])))

            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return
    print("- Finished Flipping Bits")
            
'''
Swap the types of JSON Fields to other types
'''
def swap_types(data: json, filepath):
    global crashed
    print("> Swapping types of JSON Fields")
    keys = data.keys()

    for keyValue in keys:
        for type in type_swaps_arr:
            d = copy.deepcopy(data)
            
            d[keyValue] = type

            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return
    print("- Finished Swapping Types")
