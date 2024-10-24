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
JPEG_EXIF = b'\xFF\xD8\xFF\xE1????\x45\x78\x69\x66\x00\x00' # Not sure what this one is meant to be or if it is meant to include the ????
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
    NO_BYTES, JPEG_1, JPEG_2, JPEG_JFIF, JPEG_EXIF, BITMAP, FITS, GIF, GKSM,
    IRIS, ITC, NIFF, PM, PNG, POSTSCRIPT, SUN_RASTER, TIFF_MOT, TIFF_INT, XCF,
    XFIG, XPM, BZIP, COMPRESS, GZIP, PKZIP, TAR_POSIX, MS_DOS, ELF
]

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
