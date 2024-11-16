from pypdf import PdfWriter
import copy
import random
import os
import threading
import time
from payload_handler import *
from utils import *

# Configuration options
SEE_INPUTS = False
SEE_OUTPUTS = False
MAX_THREADS = 5
TIMEOUT_SECONDS = 60

# Globals for thread management
threads = []
crashed = False
kill = False

# For tracking unique paths
found_paths = []

'''
Returns whether the given data is a valid PDF or not
'''
def is_pdf(words):
    try:
        print("trying pdf")

        # test if first few characters in given data are %PDF
        if words[:4] == b"%PDF":
            return True
    except Exception:
        return False
    return False

'''
Sends a given input to a process and returns whether it crashes
'''
def send_to_process(payload, filepath):
    global crashed, kill
    temp_file = "./temp_fuzzed.pdf"

    try:
        # Create the temp file
        with open(temp_file, "wb") as f:
            f.write(payload)

        # Send the temp file to the process (e.g., running the binary with the mutated PDF)
        # crashed, poutput, pcode = send_payload(temp_file, filepath, SEE_INPUTS, SEE_OUTPUTS)
        crashed, poutput, pcode = send_payload(f, filepath, SEE_INPUTS, SEE_OUTPUTS)
        f.close()

        if crashed:
            # If the process crashes, log the details
            handle_logging(payload, filepath, pcode, len(found_paths), time.time() - start)

            # Cleanup: only remove the temp file if it exists
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return True
        elif poutput not in found_paths:
            # If we get a new output, add it to the queue for further fuzzing
            found_paths.append(poutput)
            add_to_thread_queue(filepath, payload)

    except Exception as e:
        print(f"Error occurred while processing the temporary file: {e}")
        return False

    # Cleanup: only remove the temp file if it exists
    # if os.path.exists(temp_file):
    #     os.remove(temp_file)

    return False


'''
Main function call to begin fuzzing PDF input binaries
'''
def fuzz_pdf(filepath, words):
    global start
    start = time.time()

    # Save the original PDF payload for reference
    send_to_process(words, filepath)

    # Begin mutations
    if perform_mutation(words, filepath):
        print_crash_found()
        return

    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()

'''
Adds a mutation thread to the queue
'''
def add_to_thread_queue(filepath, data):
    global threads
    threads.append(threading.Thread(target=mutate_structure, args=(data, filepath)))
    threads.append(threading.Thread(target=mutate_metadata, args=(data, filepath)))
    threads.append(threading.Thread(target=insert_random_bytes, args=(data, filepath)))
    threads.append(threading.Thread(target=flip_bits_random, args=(data, filepath)))

'''
Perform mutations with threading and timeouts
'''
def perform_mutation(data, filepath):
    global threads, crashed, kill

    while len(threads) > 0 or threading.active_count() > 1:
        if time.time() - start > TIMEOUT_SECONDS:
            print("Timeout - Killing all Threads")
            kill = True
            return False
        if crashed:
            time.sleep(1)
            return True
        elif threading.active_count() >= MAX_THREADS:
            continue
        elif threads:
            t = threads.pop()
            t.start()

    return False

'''
Mutates the PDF structure by duplicating pages or adding invalid ones
'''
def mutate_structure(data, filepath):
    global crashed, kill
    try:
        reader = PdfReader(data)
        writer = PdfWriter()

        # Mutate structure by duplicating or altering pages
        for page in reader.pages:
            mutated_page = copy.deepcopy(page)
            writer.add_page(mutated_page)
            if crashed or kill: return
            if send_to_process(writer.output, filepath):
                crashed = True
                return
    except Exception:
        pass

'''
Mutates metadata by inserting junk values
'''
def mutate_metadata(data, filepath):
    global crashed, kill
    try:
        reader = PdfReader(data)
        writer = PdfWriter()

        # Copy pages to new writer
        for page in reader.pages:
            writer.add_page(page)

        # Mutate metadata
        metadata = reader.metadata
        for key in metadata.keys():
            writer.add_metadata({key: "A" * random.randint(50, 500)})
            if crashed or kill: return
            if send_to_process(writer.output, filepath):
                crashed = True
                return
    except Exception:
        pass

'''
Inserts random bytes into the PDF binary
'''
def insert_random_bytes(data, filepath):
    global crashed, kill
    for _ in range(100):
        fuzzed_data = bytearray(data)
        insert_at = random.randint(0, len(data))
        fuzzed_data.insert(insert_at, random.randint(0, 255))
        if crashed or kill: return
        if send_to_process(bytes(fuzzed_data), filepath):
            crashed = True
            return

'''
Flips random bits in the PDF binary
'''
def flip_bits_random(data, filepath):
    global crashed, kill
    for _ in range(100):
        fuzzed_data = bytearray(data)
        flip_at = random.randint(0, len(data) - 1)
        fuzzed_data[flip_at] ^= 0xFF  # Flip bits
        if crashed or kill: return
        if send_to_process(bytes(fuzzed_data), filepath):
            crashed = True
            return
