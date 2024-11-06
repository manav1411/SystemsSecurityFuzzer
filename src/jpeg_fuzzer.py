from pwn import *
import copy
from utils import *

'''
Number of Total Mutations
'''
NUM_MUTATIONS = 100

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

queue = []
found_paths = []

'''
Returns whether the given data is valid JPEG or not
( Checks the magic bytes at the start of the file )
'''
def is_jpeg(words):
	return words[:12] == b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01"

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_to_process(p, payload, filepath):
    p.sendline(payload)
    output = p.recvline()

    try: 
        output = p.recvline()
        if output == "":
            pass
        # A different traversal path has been found and hence it is added to the queue
        elif output not in found_paths:
            # TODO: NOT SURE IF WE SHOULD KEEP THIS IN, STOPS US ITERATING OVER INPUTS THAT ARE DEEMED INVALID
            if not ("invalid" in output or "Invalid" in output):
                queue.append(payload) # Add the current payload into the queue
                found_paths.append(output) # Adds the output so we don't encounter it again and keep appending
                print_new_path_found()
    except:
        print("Exception in Recvline Caused")

    p.proc.stdin.close()

    code = p.poll(True)
    
    if code != 0:
        write_crash_output(filepath, str(payload))
        return True
    else:
        return False

'''
Main function call to begin fuzzing JSON input binaries
'''
def fuzz_jpeg(filepath, words):
    queue.append(words)

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
def perform_mutation(filepath, data, i):
    if i == 0:
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
        if reverse_bytes(filepath, data):
            return True
    else:
        return False

'''
Replaces special bytes with other special bytes
'''
def swap_jpeg_bytes(filepath, data):
    print("Swapping JPEG Bytes to Other Forms")
    for original in file_struct_arr:
        for replacement in file_struct_arr:
            if (original is not replacement):
                print(f"Replacing {original} with {replacement}")
                newdata = data.replace(original, replacement)

                if send_to_process(get_process(filepath), newdata, filepath):
                    return True
    return False

'''
Removes special bytes from the text
'''
def remove_jpeg_bytes(filepath, data):
    print("Removing JPEG Bytes")
    for original in file_struct_arr:
        print(f"Renmoving {original}")
        newdata = data.replace(original, b"")

        if send_to_process(get_process(filepath), newdata, filepath):
            return True
    return False

'''
Replaces the JPEG magic bytes with other formats
'''
def change_magic_bytes(filepath, data):
    print("Changing Magic Bytes")
    for magic in magic_bytes_arr:
        newdata = magic + data[12:]
        print(f"Testing {newdata}")

        if send_to_process(get_process(filepath), newdata, filepath):
            return True
    return False

'''
Changes the position of both start and end structure bytes
'''
def change_start_end_bytes(filepath, data):
    print("Swapping Start and End Bytes")
    newdata = data.replace(END_IMAGE, START_IMAGE)
    newdata = newdata.replace(START_IMAGE, END_IMAGE, 1) # only replaces the first instance

    if send_to_process(get_process(filepath), newdata, filepath):
            return True
    return False


'''
Remove random bytes
'''
def remove_random_bytes(filepath, data):
    print("Removing Random Bytes")
    for i in range(0, 100):
        newdata = remove_random_bytes_util(data, i)

        if send_to_process(get_process(filepath), newdata, filepath):
            return True
    return False

'''
Insert random bytes
'''
def insert_random_bytes(filepath, data):
    print("Inserting Random Bytes")
    for i in range(0, 100):
        newdata = insert_random_bytes_util(data, i)

        if send_to_process(get_process(filepath), newdata, filepath):
            return True
    return False

'''
Reverses the entire payload cause why not
'''
def reverse_bytes(filepath, data):
    print("Reversing the Entire Thing")
    if send_to_process(get_process(filepath), data[::-1], filepath):
            return True
    return False

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
