import io
import time
import threading
from utils import *
from payload_handler import *
from elftools.elf.elffile import ELFFile
import pwn

SEE_INPUTS = False
SEE_OUTPUTS = False
MAX_THREADS = 6
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

class elf_file:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = self.load_elf()

    def load_elf(self):
        """Reads the ELF file."""
        with open(self.filepath, 'rb') as f:
            return f.read()

    def get_section_offset(self, elf_bytes, section_name):
        # Load the ELF file from bytes
        elf_file = ELFFile(io.BytesIO(elf_bytes))

        # Iterate over the sections to find the one with the matching name
        for section in elf_file.iter_sections():
            if section.name == section_name:
                # Return the offset of the section
                return section.header['sh_offset']

        # If the section is not found, return None
        return None


    def save(self):
        """Saves the modified ELF file."""
        with open(self.filepath, 'wb') as f:
            f.write(self.data)
        print(f"Modified ELF saved at {self.filepath}")


    def modify_section_data(self, section_name, data):
        """Modifies the section data."""

        with open(self.filepath, 'rb') as f:
            words = f.read()
            section_offset = self.get_section_offset(words, section_name)
            if section_offset is None:
                print(f"Section {section_name} not found.")
                return

            # Replace the section data in the ELF file's raw data
            self.data = self.data[:section_offset] + data + self.data[section_offset+len(data):]
            print(f"Section {section_name} modified.")
            self.save()


def is_elf(words):
    """Check if the input is an ELF file."""
    return words[:4] == b'\x7fELF'


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

    if perform_mutation():
        print_crash_found()
        return

    handle_logging("", filepath, 0, len(found_paths), time.time() - start)
    print_no_crash_found()


def add_to_thread_queue(filepath, data):
    global threads
    threads.append(threading.Thread(target=send_wordlist_naughty, args=(filepath, )))
    threads.append(threading.Thread(target=send_wordlist_number, args=(filepath, )))
    threads.append(threading.Thread(target=send_massive, args=(filepath, )))
    threads.append(threading.Thread(target=add_shellcode, args=(filepath)))  # New     # New
    threads.append(threading.Thread(target=change_readonly_constants, args=(filepath, )))  # New


def perform_mutation():
    global crashed, kill, threads, start
    while (len(threads)) > 0 or threading.active_count() > 1:
        if (time.time() - start > TIMEOUT_SECONDS):
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


def add_shellcode(filepath):
    print("> Adding extra data section to ELF")

    new_section_name = ".main"
    shellcode = pwn.asm("""
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

    e = elf_file(filepath)
    e.modify_section_data(new_section_name, shellcode)


def change_readonly_constants(filepath):
    print("> Changing read-only constants in ELF")

    e = elf_file(filepath)
    e.modify_section_data(".rodata", b"sbdfuhsdbud")
    e.modify_section_data(".text", b"sbdfuhsdbud")



def modify_elf_with_wordlist(filepath, word):
    # Add word to data section of ELF, create a valid ELF file
    elf_data = modify_elf_data_section(filepath, word)
    return elf_data

def modify_elf_data_section(filepath, data):
    # Load ELF, append to data section or modify a section with the input data
    elf = elf_file(filepath)
    elf.modify_section_data('.data', data)


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
    elf = elf_file(filepath)
    elf.modify_section_data('.data', large_data)
