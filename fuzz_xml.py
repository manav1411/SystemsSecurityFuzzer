import xml.etree.ElementTree as ET
from utils import *
import subprocess
import time
import copy
import random
import json
from payload_handler import *
import threading

'''
Switch to True if you want to see the inputs being send to the binary + outputs returned
'''
SEE_INPUTS = False
SEE_OUTPUTS = False

'''
Global constants (threading-related)
'''
MAX_THREADS = 5
TIMEOUT_SECONDS = 60

'''
Global constants (mutation-related)
'''
arr_of_types = ["A" * 400, '-1389054671389658013709571389065891365890189164', json.loads('{"Name": "Jennifer Smith"}'), ["A", 1234, "Meow", -9999], 'None', 'True', 'False']
type_swaps_arr = ["A" * 2000, '-9999999999999999999999999999999999999999999999999999999999999999999', json.loads('{"Name": "Jennifer Smith","Contact Number": 7867567898,"Email": "jen123@gmail.com","Hobbies":["Reading", "Sketching", "Horse Riding"]}'), arr_of_types, 'None', '', 'True', 'False', '<random></random>', '<random>hello</random>']
keyword_arr = ['len', 'length', 'debug', 'privilege', 'admin', 'level', 'id']
keyword_swap_arr = ['0', '1', 'True', 'False', 'Yes', 'No', '999999999999999999999999999999999999999999999999999999999999999999999999999999999999']

'''
Timing Things
'''
start = 0

'''
Threads for multithreading
'''
crashed = False
kill = False
threads = []

'''
For code coverage
'''
found_paths = []

'''
Returns whether the given data is valid XML or not
'''
def is_xml(inputpath):
    try:
        ET.parse(inputpath)
    except:
        return False
    
    return True

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(payload, filepath, payload_is_tree=True):
    if payload_is_tree:
        payload = payload.getroot()
        payload = ET.tostring(payload, encoding="unicode")

    pcrashed, poutput, pcode = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)

    global crashed, kill
    crashed = pcrashed

    if kill:
        return False

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(payload, filepath, pcode, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if poutput not in found_paths and not check_start_output(poutput, found_paths):
        found_paths.append(poutput)
        # add_to_thread_queue(filepath, payload)

    return False


# def send_to_process(payload, filepath, payload_is_tree=True):
#     if payload_is_tree:
#         payload = payload.getroot()
#         payload = ET.tostring(payload, encoding="unicode")

#     if SEE_INPUTS:
#         print(payload)
#         print("end payload")
    
#     try:
#         process = subprocess.run(
#             [filepath],
#             input=payload,
#             text=True,
#             capture_output=True
#         )
        
#         # Capture the return code and output
#         code = process.returncode
#         output = process.stdout

#         if PRINT_OUTPUTS:
#             print(f"output: {output}")
        
#     except Exception as e:
#         print(f"error: {e}")
#         return False
    
#     if output == "":
#         pass
#     # A different traversal path has been found and hence it is added to the queue
#     # elif output not in found_paths:
#     #     # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
#     #     if not ("invalid" in output or "Invalid" in output):
#     #         # Add the current payload into the queue
#     #         # queue.append(ET.fromstring(payload))

#     #         # Adds the output so we don't encounter it again and keep appending 
#     #         found_paths.append(output)
#     #         print_new_path_found()
#     #         time.sleep(1)
    
#     if code != 0:
#         write_crash_output(filepath, payload)
#         return True
#     else:
#         return False


'''
Main function call to begin fuzzing XML input binaries
'''
def fuzz_xml(filepath, inputpath):
    global start
    start = time.time()
    tree = ET.parse(inputpath)

    send_to_process(tree, filepath)

    # # item is xml tree
    d = copy.deepcopy(tree)
    if perform_mutation(filepath, d):
        print_crash_found()
        return

    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()


'''
Begins the mutation process
'''
def perform_mutation(filepath, data):
    if duplicate_elements(data, filepath): return True
    if remove_elements(data, filepath): return True
    if rearrange_elements(data, filepath): return True
    if malform_xml(data, filepath): return True
    if keyword_extraction(data, filepath): return True
    if mutate_attributes(data, filepath): return True
    if mutate_text(data, filepath): return True
    if flip_bits(data, filepath): return True
    if swap_types(data, filepath): return True
    return False


'''
Adds 2000, 100, 10 duplicate elements and then duplicates whole tree
'''
def duplicate_elements(data, filepath):
    # print("> Testing Duplicating elements")
    for i in [2000, 100, 10]:
        # print(f"  > Adding {i} Duplicate Elements")
        d = copy.deepcopy(data)
        root = d.getroot()
        dup = root[0]

        for j in range(i):
            root.append(dup)

        if send_to_process(d, filepath):
            return True
    
    # Duplicate whole tree
    d1 = copy.deepcopy(data)
    d2 = copy.deepcopy(data)
    r1 = d1.getroot()
    r2 = d2.getroot()
    r1.append(r2)

    if send_to_process(d1, filepath):
        return True
    
    return False

'''
Removes each of the root child XML nodes - both one at a time & cumulatively
'''
def remove_elements(data, filepath):
    # print("> Testing Removing Fields")
    root = data.getroot()
    i = 0
    d1 = copy.deepcopy(data)
    r1 = d1.getroot()
    for child in root:
        d2 = copy.deepcopy(data)
        r2 = d2.getroot()
        # print(f"    > Deleting Field {child.tag}")
        r2.remove(r2[i])
        i = i + 1

        if send_to_process(d2, filepath):
            return True
        
        r1.remove(r1[0])
        if send_to_process(d1, filepath):
            return True
    
    return False

'''
Rearrranges the root child XML nodes
'''
def rearrange_elements(data, filepath):
    # print("> Testing Rearrange Fields")
    root = data.getroot()
    n = len(list(root))
    d = copy.deepcopy(data)
    r = d.getroot()

    children = list(r)
    random.shuffle(children)
    for child in children:
        r.append(child)
    
    # Remove the first n children (so no duplicates)
    for i in range(n):
        r.remove(r[i])

    if send_to_process(d, filepath):
        return True
       
    return False

'''
Produces malformed xml (without closing tag / only partial data)
'''
def malform_xml(data, filepath):
    # print("> Testing malforming xml")

    d = copy.deepcopy(data)
    r = d.getroot()
    xml_str = ET.tostring(r, encoding="unicode")

    # xml without closing tag
    if send_to_process(xml_str[:-1], filepath, payload_is_tree=False):
        return True
    
    # send only half the payload
    n = len(xml_str)
    if send_to_process(xml_str[:-n], filepath, payload_is_tree=False):
        return True
       
    return False


'''
Extracts keywords from element attributes and mutates them if found
'''
def keyword_extraction(data, filepath):
    # print("> Keyword extraction")
    parent = data.getroot()

    for child in parent.iter():
        for item in child.items():
            if (item[0]).lower() in keyword_arr:
                for mutate in keyword_swap_arr:
                    d = copy.deepcopy(data)
                    child.set(item[0], mutate)

                    if (send_to_process(d, filepath)):
                        return True

    return False


'''
Mutates attributes within the xml to different values
'''
def mutate_attributes(data, filepath):
    # print("> Mutating Attributes")
    parent = data.getroot()

    for child in parent.iter():
        for item in child.items():
            try: 
                int(item[1], 0)
                with open('./wordlists/allnumber.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        child.set(item[0], line)

                        if (send_to_process(d, filepath)):
                            file.close()
                            return True
                    file.close()

            except:
                with open('./wordlists/naughtystrings.txt', 'r') as file:
                    for line in file:
                        d = copy.deepcopy(data)
                        child.set(item[0], line)

                        if (send_to_process(d, filepath)):
                            file.close()
                            return True
                    file.close()

    return False

'''
Mutates text within the xml to different values
'''
def mutate_text(data, filepath):
    # print("> Mutating Text")
    parent = data.getroot()

    for child in parent.iter():
        # print(child.text)
        with open('./wordlists/naughtystrings.txt', 'r') as file:
            for line in file:
                d = copy.deepcopy(data)
                child.text = line

                if (send_to_process(d, filepath)):
                    file.close()
                    return True
            file.close()

    return False


'''
Mutates attributes with the bits randomly flipped
'''
def flip_bits(data, filepath):
    # print("> Flipping Bits")

    parent = data.getroot()
    for child in parent.iter():
        for item in child.items():
            for i in range(0, 100):
                d = copy.deepcopy(data)
                
                if is_str(item[1]):
                    child.set(item[0], ubits_to_string(uflip_bits_random(ustring_to_bits(item[1]))))

                if (send_to_process(d, filepath)):
                    return True
            
    return False


'''
Swap the attributes of XML elements to other tags
'''
def swap_types(data: json, filepath):
    # print("Swapping types of XML attributes")
    parent = data.getroot()
    for child in parent.iter():
        for item in child.items():
            for type in type_swaps_arr:
                d = copy.deepcopy(data)

                child.set(item[0], type)

                if (send_to_process(d, filepath)):
                    return True
    return False