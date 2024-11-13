import json
import copy
import time
from utils import *
from payload_handler import *
from random import randbytes, randint
import threading

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = True 
SEE_OUTPUTS = True
MAX_THREADS = 5

'''
Mutations defines
'''
arr_of_types = ["A" * 400, -1389054671389658013709571389065891365890189164, json.loads('{"Name": "Jennifer Smith"}'), ["A", 1234, "Meow", -9999], None, True, False]
type_swaps_arr = ["A" * 2000, -9999999999999999999999999999999999999999999999999999999999999999999, json.loads('{"Name": "Jennifer Smith","Contact Number": 7867567898,"Email": "jen123@gmail.com","Hobbies":["Reading", "Sketching", "Horse Riding"]}'), arr_of_types, None, True, False]

'''
For code coverage
'''
found_paths = []

'''
Timing Things
'''
start = 0

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
    p = json.dumps(payload)
    pcrashed, poutput, pcode = send_payload(p, filepath, SEE_INPUTS, SEE_OUTPUTS)

    global crashed
    crashed = pcrashed

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(p, filepath, pcode, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if poutput not in found_paths and not check_start_output(poutput, found_paths):
        found_paths.append(poutput)
        add_to_thread_queue(filepath, payload)

    return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_json(filepath, words):
    global start
    start = time.time()
    w = json.loads(words)

    send_to_process(w, filepath)

    if perform_mutation():
        print_crash_found()
        return

    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()

'''
Adds a given payloads threads to the queue
'''
def add_to_thread_queue(filepath, data):
    global threads
    threads.append(threading.Thread(target=add_fields, args=(data, filepath)))
    threads.append(threading.Thread(target=remove_fields, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_with_nums, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_with_strings, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits_sequential, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits_random, args=(data, filepath)))
    threads.append(threading.Thread(target=change_bytes_sequential, args=(data, filepath)))
    threads.append(threading.Thread(target=insert_bytes_random, args=(data, filepath)))
    threads.append(threading.Thread(target=swap_types, args=(data, filepath)))

'''
Continously runs threads until the program crashes or there
are no more processes to try and mutate
'''
def perform_mutation():
    global crashed, threads
    while (len(threads)) > 0 or threading.active_count() > 1:
        if crashed: 
            return True
        elif threading.active_count() >= MAX_THREADS:
            continue
        elif len(threads) != 0:
            t = threads.pop()
            t.start()

    return False

'''
Adds Fields to the JSON
'''
def add_fields(data: json, filepath):
    global crashed
    for i in range(1,1001):
        d = copy.deepcopy(data)

        for j in range (0, i):
            d[f"RandomField{j}"] = f"RandomValue{j}"

        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Removes Fields to the JSON
'''
def remove_fields(data: json, filepath):
    global crashed
    keys = data.keys()  
    for keyValue in keys:
        d = copy.deepcopy(data)
        del d[keyValue]
        if crashed: return
        if send_to_process(d, filepath):
            crashed = True
            return

'''
Mutates fields within the JSON to different number values
'''
def mutate_with_nums(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
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

'''
Mutates fields within the JSON to different number values
'''
def mutate_with_strings(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
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

'''
Sequentially flips bits one at a time
'''
def flip_bits_sequential(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
        length = 0
        if is_num(data[keyValue]):
            bits = unumber_to_bits(data[keyValue])
            length = len(bits)
        elif is_str(data[keyValue]):
            bits = ustring_to_bits(data[keyValue])
            length = len(bits)
        for i in range(0, length):
            d = copy.deepcopy(data)

            if is_num(d[keyValue]):
                d[keyValue] = ubits_to_number(uflip_bits_at(bits, i))
            elif is_str(d[keyValue]):
                d[keyValue] = ubits_to_string(uflip_bits_at(bits, i))

            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

'''
Sequentially flips randomly
'''
def flip_bits_random(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
        for i in range(0, 100):
            d = copy.deepcopy(data)

            if is_num(d[keyValue]):
                d[keyValue] = ubits_to_number(uflip_bits_random(unumber_to_bits(d[keyValue])))
            elif is_str(d[keyValue]):
                d[keyValue] = ubits_to_string(uflip_bits_random(ustring_to_bits(d[keyValue])))

            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

'''
Sequentially flips randomly
'''
def change_bytes_sequential(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
        length = 0
        if is_num(data[keyValue]):
            length = len(str(data[keyValue]))
        elif is_str(data[keyValue]):
            length = len(data[keyValue])
        else:
            continue

        if length > 100: length = 100
        for i in range(0, length):
            d = copy.deepcopy(data)

            d[keyValue] = replace_byte_at(data[keyValue], i, 0xFF)
            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

            d[keyValue] = replace_byte_at(data[keyValue], i, 0xFFFF)
            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

            d[keyValue] = replace_byte_at(data[keyValue], i, 0x00)
            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

'''
Inserts a random number of bytes at a random location
'''
def insert_bytes_random(data: json, filepath):
    global crashed
    keys = data.keys()
    for keyValue in keys:
        for i in range(0, 200):
            d = copy.deepcopy(data)
            if is_num(data[keyValue]): bytes = d[keyValue].to_bytes(2, 'little')
            elif is_str(data[keyValue]): bytes = d[keyValue].encode('utf-8')
            else: continue
            if is_num(data[keyValue]):
                d[keyValue] = int.from_bytes(insert_random_bytes_util(bytes, 15))
            elif is_str(data[keyValue]):
                d[keyValue] = insert_random_bytes_util(bytes, 200).decode('utf-8')
            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return

'''
Modifies certain fields to different fields with changing values
'''
def modify_fields(data: json, filepath):
    global crashed
    with open('./wordlists/keywords.txt', 'r') as file:
        for line in file:
            for type in type_swaps_arr:
                d = copy.deepcopy(data)
                
                d[line] = type
                
                if crashed:
                    file.close()
                    return
                if send_to_process(d, filepath):
                    crashed = True
                    return
        file.close()

'''
Swap the types of JSON Fields to other types
'''
def swap_types(data: json, filepath):
    global crashed
    keys = data.keys()

    for keyValue in keys:
        for type in type_swaps_arr:
            d = copy.deepcopy(data)
            
            d[keyValue] = type

            if crashed: return
            if send_to_process(d, filepath):
                crashed = True
                return
            
'''
Helper
'''
def insert_random_bytes_util(data, num_to_insert):
    if isinstance(data, bytes):
        # Convert to a mutable bytearray if input is immutable bytes
        data = bytearray(data)
    elif not isinstance(data, bytearray):
        raise TypeError("Input must be bytes or bytearray.")
        
    length = len(data)
    
    for _ in range(num_to_insert):
        # Generate a random byte and a random insertion position
        random_byte = random.randint(0, 255)
        position = random.randint(0, length)
        
        # Insert the random byte at the chosen position
        data.insert(position, random_byte)
        
        # Update the length for the next insertion position
        length += 1
    
    return bytes(data) if isinstance(data, bytes) else data