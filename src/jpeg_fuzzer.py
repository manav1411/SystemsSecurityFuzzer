import copy
from pwn import *
from fuzzer import write_crash_output, get_process

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 5

'''
File Structure Bytes of JPEG File - Don't know how important these are in fuzzing
( https://docs.fileformat.com/image/jpeg/ )
'''
START_IMAGE = b'\xFF\xD8'
START_FRAME_0 = b'\xff\xc0'
START_FRAME_1 = b'\xff\xc2'
HUFFMAN_TABLES = b'\xff\xc4'
QUANTIZATION_TABLE = b'\xff\xdb'
RESTART_INTERVAL = b'\xff\xdd'
START_SCAN = b'\xff\xda'
COMMENT = b'\xff\xfe'
END_IMAGE = b'\xff\xd9'

'''
Magic Bytes of Different File Types
'''
# TODO

'''
Returns whether the given data is valid JPEG or not
( Checks the magic bytes at the start of the file )
'''
def is_jpeg(words):
	return words[:12] == b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01"

'''
Sends a given input to a process, then returns whether the process crashes or not
> JSON specific <
'''
def send_to_process(p, payload, filepath):
    p.sendline(payload)
    p.proc.stdin.close()

    code = p.poll(True)
    
    if code != 0:
        write_crash_output(filepath, payload)
        return True
    else:
        return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_jpeg(filepath, words):
    for i in range(0, NUM_MUTATIONS):
        d = copy.deepcopy(words)
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
def perform_mutation(filepath, data, i):
    if i == 0:          # Testing Default Payload
        print("> Testing Normal Payload")
        if send_to_process(get_process(filepath), data, filepath):
            return True
    elif i == 1:
        print("> Testing Sending Nothing")
        if send_to_process(get_process(filepath), '', filepath):
            return True
    elif i == 2:
        if swap_jpeg_bytes(filepath, data):
            return True
    elif i == 3:
        if remove_jpeg_bytes(filepath, data):
            return True
    elif i == 4:
        if change_magic_bytes(filepath, data):
            return True
    elif i == 5:
        if change_start_end_bytes(filepath, data):
            return True
    elif i == 6:
        if remove_random_bytes(filepath, data):
            return True
    elif i == 7:
        if insert_random_bytes(filepath, data):
            return True
    elif i == 8:
        if insert_0xff_bytes(filepath, data):
            return True
    elif i == 9:
        if reverse_bytes(filepath, data):
            return True
    else:
        return False

'''
Replaces special bytes with other special bytes
'''
def swap_jpeg_bytes(filepath, data):
    return False

'''
Removes special bytes from the text
'''
def remove_jpeg_bytes(filepath, data):
    return False

'''
Replaces the JPEG magic bytes with other formats
'''
def change_magic_bytes(filepath, data):
    return False

'''
Changes the position of both start and end structure bytes
'''
def change_start_end_bytes(filepath, data):
    return False

'''
Remove random bytes
'''
def remove_random_bytes(filepath, data):
    return False

'''
Insert random bytes
'''
def insert_random_bytes(filepath, data):
    return False

'''
Insert 0xFF bytes
'''
def insert_0xff_bytes(filepath, data):
    return False

'''
Removes special bytes from the text
'''
def reverse_bytes(filepath, data):
    return False
