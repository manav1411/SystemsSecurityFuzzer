import copy
import string
import random
import time
import threading
from utils import *
from payload_handler import *
from elftools.elf.elffile import ELFFile
from pwn import asm

SEE_INPUTS = False
SEE_OUTPUTS = False
MAX_THREADS = 5
TIMEOUT_SECONDS = 60

# Format specifiers to target potential format string vulnerabilities
format_string_specifiers = ['%', 's', 'p', 'd', 'c', 'u', 'x', 'n']

# Control characters to insert and potentially trigger unexpected behavior
ascii_controls = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
                  '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11',
                  '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a',
                  '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x7f']

found_paths = []
start = 0
crashed = False
kill = False
threads = []

class ELF:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = self.load_elf()

    def load_elf(self):
        """Reads the ELF file."""
        with open(self.filepath, 'rb') as f:
            return f.read()

    def get_section_offset(self, section_name):
        """Returns the offset of the section in the ELF file."""
        with open(self.filepath, 'rb') as f:
            elf = ELFFile(f)

            for section in elf.iter_sections():
                if section.name == section_name:
                    # Return the offset where the section starts in the file
                    return section['sh_offset']
        return None  # Not found

    def modify_section_data(self, section_name, data):
        """Modifies the section data."""
        # Find the offset for the section we want to modify
        section_offset = self.get_section_offset(section_name)
        if section_offset is None:
            print(f"Section {section_name} not found.")
            return

        # Replace the section data in the ELF file's raw data
        self.data = self.data[:section_offset] + data + self.data[section_offset+len(data):]
        print(f"Section {section_name} modified.")

    def add_data_to_section(self, section_name, data):
        """Adds data to an appropriate section in the ELF file."""
        self.modify_section_data(section_name, data.encode())

    def save(self):
        """Saves the modified ELF file."""
        with open(self.filepath, 'wb') as f:
            f.write(self.data)
        print(f"Modified ELF saved at {self.filepath}")


def is_elf(file_path):
    try:
        with open(file_path, 'rb') as file:
            elf = ELFFile(file)

            magic = elf.header['e_ident']

            # Check if the magic number matches the ELF signature (0x7f, 'E', 'L', 'F')
            if magic[:4] == b'\x7fELF':
                return True
            else:
                return False
    except Exception as e:
        return False


def send_to_process(payload, filepath):
    pcrashed, poutput, pcode = send_payload(payload, filepath, SEE_INPUTS, SEE_OUTPUTS)
    global crashed, kill
    crashed = pcrashed
    if kill:
        return False
    if crashed:
        global start
        handle_logging(payload, filepath, pcode, len(found_paths), time.time() - start)
        return True
    if poutput not in found_paths and not check_start_output(poutput, found_paths):
        found_paths.append(poutput)
        add_to_thread_queue(filepath, payload)
    return False

def fuzz_elf(filepath, words):
    global start
    start = time.time()

    send_to_process(words, filepath)

    if perform_mutation(filepath, words):
        print_crash_found()
        return

    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()

def add_to_thread_queue(filepath, data):
    global threads
    threads.append(threading.Thread(target=send_wordlist_naughty, args=(filepath, )))
    threads.append(threading.Thread(target=send_wordlist_number, args=(filepath, )))
    threads.append(threading.Thread(target=flip_bits, args=(filepath, data)))
    threads.append(threading.Thread(target=add_long_strings_ascii, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_long_strings_ascii, args=(filepath, data, 500)))
    threads.append(threading.Thread(target=add_long_strings_printable, args=(filepath, data, 0)))
    threads.append(threading.Thread(target=add_long_strings_printable, args=(filepath, data, 500)))
    threads.append(threading.Thread(target=send_massive, args=(filepath, )))
    threads.append(threading.Thread(target=send_format_strings, args=(filepath, )))
    threads.append(threading.Thread(target=add_extra_data_section, args=(filepath, data)))  # New
    threads.append(threading.Thread(target=modify_elf_header, args=(filepath, )))           # New
    threads.append(threading.Thread(target=change_readonly_constants, args=(filepath, )))  # New

def perform_mutation(filepath, data):
    global crashed, kill, threads, start
    while len(threads) > 0 or threading.active_count() > 1:
        if time.time() - start > TIMEOUT_SECONDS:
            print("Timeout - Killing all Threads")
            kill = True
            return False
        if crashed:
            return True
        elif threading.active_count() >= MAX_THREADS:
            continue
        elif len(threads) != 0:
            t = threads.pop()
            t.start()

    return False


def add_extra_data_section(filepath, data):
    print("> Adding extra data section to ELF")
    with open(filepath, 'r+b') as f:
        elf = ELFFile(f)
        new_section_name = ".win"
        new_section_data = asm("""
            xor rax, rax
            push rax
            mov rax, 0x68732f2f6e69622f
            push rax
            mov rdi, rsp

            xor rsi, rsi
            xor rdx, rdx
            mov rax, 59
            syscall
            """, arch='amd64')

        elf.add_section(new_section_name, new_section_data)
        f.seek(0)
        elf.write(f)

def modify_elf_header(filepath):
    print("> Modifying ELF header")
    with open(filepath, 'r+b') as f:
        elf = ELFFile(f)
        header = elf.header
        header['e_entry'] = 0xdeadbeef  # Change entry point to a new value
        f.seek(0)
        elf.write(f)


def change_readonly_constants(filepath):
    print("> Changing read-only constants in ELF")
    with open(filepath, 'r+b') as f:
        elf = ELFFile(f)
        rodata_section = elf.get_section_by_name('.rodata')
        new_constant = b"Super long constant data that could overflow buffers" * 30
        rodata_section.data = new_constant  # Modify the section's data with a long constant
        f.seek(0)
        elf.write(f)


def send_wordlist_number(filepath):
    global crashed, kill
    print('> Sending Wordlist allnumber')
    with open('./wordlists/allnumber.txt', 'r') as file:
        for line in file:
            if crashed or kill:
                file.close()
                return
            elf_payload = modify_elf_with_wordlist(filepath, line)
            if send_to_process(elf_payload, filepath):
                file.close()
                crashed = True
                return
    print("- Finished Sending All Numbers")

def modify_elf_with_wordlist(filepath, word):
    # Add word to data section of ELF, create a valid ELF file
    elf_data = modify_elf_data_section(filepath, word)
    return elf_data

def modify_elf_data_section(filepath, data):
    # Load ELF, append to data section or modify a section with the input data
    elf = ELF(filepath)
    elf.add_data_to_section(data)
    return elf.save()


def send_wordlist_naughty(filepath):
    global crashed, kill
    print("> Sending wordlist naughtystrings")
    with open('./wordlists/naughtystrings.txt', 'r') as file:
        for line in file:
            if crashed or kill:
                file.close()
                return
            elf_payload = modify_elf_with_wordlist(filepath, line)
            if send_to_process(elf_payload, filepath):
                file.close()
                crashed = True
                return
    print("- Finished Sending All Strings")

def flip_bits(filepath, data):
    global crashed, kill
    print("> Flipping bits")
    for num in range(0, len(data) * 50):
        d = copy.deepcopy(data)
        flipped = uflip_bits_random(ustring_to_bits(str(d)))
        elf_payload = modify_elf_with_flipped_bits(filepath, flipped)
        if crashed or kill: return
        if send_to_process(elf_payload, filepath):
            crashed = True
            return
    print("- Finished Bit Flipping")

def modify_elf_with_flipped_bits(filepath, flipped_bits):
    # Flip bits in ELF and ensure it's a valid ELF after the operation
    elf = ELF(filepath)
    elf.flip_bits(flipped_bits)
    return elf.save()


def add_long_strings_ascii(filepath, data, start):
    global crashed, kill
    print("> Adding in long strings (ASCII)")
    for num in range(start, start + 500):
        d = copy.deepcopy(data)
        longdata = d + ((random.choice(string.ascii_letters).encode() * num))
        elf_payload = modify_elf_with_long_strings(filepath, longdata)
        if crashed or kill: return
        if send_to_process(elf_payload, filepath):
            crashed = True
            return
    print(f"- Finished Long Strings ASCII (Start = {start})")

def modify_elf_with_long_strings(filepath, long_string):
    # Modify ELF with long ASCII strings
    elf = ELF(filepath)
    elf.add_string_to_section(long_string)
    return elf.save()

def add_long_strings_printable(filepath, data, start):
    global crashed, kill
    print("> Adding in long strings (Printable)")
    for num in range(start, start + 500):
        d = copy.deepcopy(data)
        longdata = d + (random.choice(string.printable).encode() * num)
        elf_payload = modify_elf_with_long_strings(filepath, longdata)
        if crashed or kill: return
        if send_to_process(elf_payload, filepath):
            crashed = True
            return
    print(f"- Finished Long Strings Printable (Start = {start})")

def send_massive(filepath):
    global crashed, kill
    print("> Sending Massive Strings")
    for num in range(1, 101):
        massive = b'A' * (1000 * num)
        elf_payload = modify_elf_with_large_data(filepath, massive)
        if crashed or kill: return
        if send_to_process(elf_payload, filepath):
            crashed = True
            return
    print("- Finished Sending Massive")

def modify_elf_with_large_data(filepath, large_data):
    elf = ELF(filepath)
    elf.add_data_to_section(large_data)
    return elf.save()

def send_format_strings(filepath):
    global crashed, kill
    print("> Sending Format String Payloads")
    for num in range(0, 51):
        for format_spec in format_string_specifiers:
            if num == 0:
                format_string = f'%{format_spec}'
            else:
                format_string = f'%{num}${format_spec}'

            elf_payload = modify_elf_with_format_string(filepath, format_string)
            if crashed or kill: return
            if send_to_process(elf_payload, filepath):
                crashed = True
                return
    print("- Finished Sending Format Strings")

def modify_elf_with_format_string(filepath, format_string):
    """ Inject format string into the ELF file """
    elf = ELF(filepath)
    elf.add_format_string(format_string)
    return elf.save()
