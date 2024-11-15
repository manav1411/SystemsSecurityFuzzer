import subprocess
from utils import *
import time
import os
import subprocess
from utils import *
import time

'''
Sends a given input to a process, then returns whether the process crashes or not
'''
def send_payload(payload, filepath, see_inputs, see_outputs):
    if see_inputs:
        print(payload)
    
    try:
        if isinstance(payload, bytes):
            process = subprocess.run(
                [filepath],
                input=payload,
                capture_output=True
            )
        else:
            process = subprocess.run(
                [filepath],
                input=payload,
                text=True,
                capture_output=True
            )
        
        # Capture the return code and output
        code = process.returncode
        output = process.stdout

        if see_outputs:
            print(output)
        
    except Exception as e:
        print(e)
        return False, "", 0

    if code != 0:
        return True, output, code
    else:
        return False, output, code
    
'''
Handles logging information when a binary does crash
'''
def handle_logging(payload, filepath, code, num_paths, ptime):
    output_file = './logs.txt'
    if code != 0:
        if isinstance(payload, bytes):
            bad = './fuzzer_output/bad_' + filepath[11:] + '.txt'
            # Creates directories for output the first time it's called
            os.makedirs(os.path.dirname(bad), exist_ok=True)
            with open(bad, 'wb') as badfile:
                badfile.write(payload)
                badfile.close()
        else:
            bad = './fuzzer_output/bad_' + filepath[11:] + '.txt'
            # Creates directories for output the first time it's called
            os.makedirs(os.path.dirname(bad), exist_ok=True)
            with open(bad, 'w') as badfile:
                badfile.write(payload)
                badfile.close()
        
    with open(output_file, 'a') as file:
        file.write(f'''
Binary: {filepath[11:]}
Program Exited with: {code} | {get_signal(code)}
Number of Paths Found: {num_paths}
Total time Taken: {ptime}''')
        file.close()

'''
Returns a string about which signal was received that wasnt 0
'''
def get_signal(code):
    if code == signal.SIGABRT or code == -6: return "SIGABRT - abort() Call"
    elif code == signal.SIGALRM or code == -14: return "SIGALRM - alarm() Call"
    elif code == signal.SIGBUS or code == -10: return "SIGBUS - Bus Error (Bad Memory Access)"
    elif code == signal.SIGFPE or code == -8: return "SIGFPE - Floating Point Exception"
    elif code == signal.SIGHUP or code == -1: return "SIGHUP - Hangup Detected on Controlling Terminal or Death of Controlling Process"
    elif code == signal.SIGILL or code == -4: return "SIGILL - Illegal Instruction"
    elif code == signal.SIGINT or code == -2: return "SIGINT - Interrupt from Keyboard (CTRL + C) USER CAUSED"
    elif code == signal.SIGKILL or code == -9: return "SIGKILL - Kill Signal"
    elif code == signal.SIGPIPE or code == -13: return "SIGPIPE - Broken Pipe"
    elif code == signal.SIGSEGV or code == -11: return "SIGSEGV - Segfault Detected (Invalid Memory Reference.)"
    elif code == signal.SIGTERM or code == -15: return "SIGTERM - Termination Signal"
    elif code == signal.SIGUSR2 or code == -12: return "SIGUSR2 - User Defined Signal (Unknown)"
    elif code == 0: return "Normal Return (No Crash)"
    else: return "Unknown Signal Received"

'''
Checks whether a string match occurs within the first n chars to scan for duplicate outputs
'''
def check_start_output(o, paths):
    if len(o) == 0: return False
    length = 10 if len(o) > 10 else len(o) / 2
    for path in paths:
        if o[:length] in path:
            return True
    return False