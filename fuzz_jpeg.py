import copy
import time
import threading
from utils import *
from payload_handler import *

'''
Switch to True if you want to see the inputs being send to the binary
'''
SEE_INPUTS = False
SEE_OUTPUTS = False
MAX_THREADS = 5

'''
File Structure Bytes of JPEG File - Don't know how important these are in fuzzing
( https://docs.fileformat.com/image/jpeg/ )
'''
START_IMAGE = b'\xFF\xD8'
START_FRAME_0 = b'\xFF\xC0'
START_FRAME_1 = b'\xFF\xC2'
HUFFMAN_TABLES = b'\xFF\xC4'
QUANTIZATION_TABLE = b'\xFF\xDB'
RESTART_INTERVAL = b'\xFF\xDD'
START_SCAN = b'\xFF\xDA'
COMMENT = b'\xFF\xFE'
END_IMAGE = b'\xFF\xD9'

file_struct_arr = [
    START_IMAGE, START_FRAME_0, START_FRAME_1, HUFFMAN_TABLES,
    QUANTIZATION_TABLE, RESTART_INTERVAL, START_SCAN, COMMENT, END_IMAGE
]

'''
Magic Bytes of Different File Types - Don't know how many of these we need
'''
NO_BYTES = b''
JPEG_1 = b'\xFF\xD8\xFF\xDB'
JPEG_2 = b'\xFF\xD8\xFF\xEE'
JPEG_JFIF = b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01'
BITMAP = b'\x42\x4d'
FITS = b'\x53\x49\x4d\x50\x4c\x45'
GIF = b'\x47\x49\x46\x38'
GKSM = b'\x47\x4b\x53\x4d'
IRIS = b'\x01\xda'
ITC = b'\xf1\x00\x40\xbb'
NIFF = b'\x49\x49\x4e\x31'
PM = b'\x56\x49\x45\x57'
PNG = b'\x89\x50\x4e\x47'
POSTSCRIPT = b'\x25\x21'
SUN_RASTER = b'\x59\xa6\x6a\x95'
TIFF_MOT = b'\x4d\x4d\x00\x2a'
TIFF_INT = b'\x49\x49\x2a\x00'
XCF = b'\x67\x69\x6d\x70\x20\x78\x63\x66\x20\x76'
XFIG = b'\x23\x46\x49\x47'
XPM = b'\x2f\x2a\x20\x58\x50\x4d\x20\x2a\x2f'
BZIP = b'\x42\x5a'
COMPRESS = b'\x1f\x9d'
GZIP = b'\x1f\x8b'
PKZIP = b'\x50\x4b\x03\x04'
TAR_POSIX = b'\x75\x73\x74\x61\x72'
MS_DOS = b'\x4d\x5a'
ELF = b'\x7f\x45\x4c\x46'

magic_bytes_arr = [
    NO_BYTES, JPEG_1, JPEG_2, JPEG_JFIF, BITMAP, FITS, GIF, GKSM,
    IRIS, ITC, NIFF, PM, PNG, POSTSCRIPT, SUN_RASTER, TIFF_MOT, TIFF_INT, XCF,
    XFIG, XPM, BZIP, COMPRESS, GZIP, PKZIP, TAR_POSIX, MS_DOS, ELF
]

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
Returns whether the given data is valid JPEG or not
( Checks the magic bytes at the start of the file )
'''
def is_jpeg(words):
	return words[:12] == b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01"

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(payload, filepath):
    _crashed, _output, _code = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
    
    global crashed
    crashed = _crashed

    # Handles the program logging if it crashes
    if crashed:
        global start
        handle_logging(payload, filepath, _code, len(found_paths), time.time() - start)
        return True

    # If a new output is found it is added to the queue
    if _output not in found_paths:
        found_paths.append(_output)
        add_to_thread_queue(filepath, payload)

    return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_jpeg(filepath, words):
    global start
    start = time.time()

    send_to_process(words, filepath)

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
    threads.append(threading.Thread(target=swap_jpeg_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=remove_jpeg_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=change_magic_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=change_start_end_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=remove_random_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=insert_random_bytes, args=(filepath, data)))
    threads.append(threading.Thread(target=reverse_bytes, args=(filepath, data)))

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
Replaces special bytes with other special bytes
'''
def swap_jpeg_bytes(filepath, data):
    global crashed
    for original in file_struct_arr:
        for replacement in file_struct_arr:
            if (original is not replacement):
                newdata = data.replace(original, replacement)

                if crashed: return
                if send_to_process(newdata, filepath):
                    crashed = True
                    return

'''
Removes special bytes from the text
'''
def remove_jpeg_bytes(filepath, data):
    global crashed
    for original in file_struct_arr:
        newdata = data.replace(original, b"")

        if crashed: return
        if send_to_process(newdata, filepath):
            crashed = True
            return

'''
Replaces the JPEG magic bytes with other formats
'''
def change_magic_bytes(filepath, data):
    global crashed
    for magic in magic_bytes_arr:
        newdata = magic + data[12:]
        if crashed: return
        if send_to_process(newdata, filepath):
            crashed = True
            return

'''
Changes the position of both start and end structure bytes
'''
def change_start_end_bytes(filepath, data):
    global crashed
    newdata = data.replace(END_IMAGE, START_IMAGE)
    newdata = newdata.replace(START_IMAGE, END_IMAGE, 1) # only replaces the first instance

    if crashed: return
    if send_to_process(newdata, filepath):
        crashed = True
        return


'''
Remove random bytes
'''
def remove_random_bytes(filepath, data):
    global crashed
    for i in range(0, 100):
        newdata = remove_random_bytes_util(data, i)

        if crashed: return
        if send_to_process(newdata, filepath):
            crashed = True
            return

'''
Insert random bytes
'''
def insert_random_bytes(filepath, data):
    global crashed
    for i in range(0, 100):
        newdata = insert_random_bytes_util(data, i)

        if crashed: return
        if send_to_process(newdata, filepath):
            crashed = True
            return

'''
Reverses the entire payload cause why not
'''
def reverse_bytes(filepath, data):
    global crashed
    if crashed: return
    if send_to_process(data[::-1], filepath):
        crashed = True
        return

'''
Helper
'''
def remove_random_bytes_util(data, num_to_remove):
    if isinstance(data, bytes):
        # Convert to a mutable bytearray if input is immutable bytes
        data = bytearray(data)
    elif not isinstance(data, bytearray):
        raise TypeError("Input must be bytes or bytearray.")
    
    length = len(data)
    if length == 0:
        return data  # Nothing to remove if the array is empty.
    
    # Determine number of bytes to remove
    if num_to_remove is None:
        num_to_remove = random.randint(1, length // 2)
    else:
        num_to_remove = min(num_to_remove, length)
    
    # Randomly select indices to remove
    indices_to_remove = sorted(random.sample(range(length), num_to_remove), reverse=True)
    
    # Remove bytes at the selected indices
    for index in indices_to_remove:
        del data[index]
    
    return bytes(data) if isinstance(data, bytes) else data

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
