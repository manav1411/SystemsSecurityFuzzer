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
    output_file = './logs/log_' + filepath[11:] + '.txt'
    if code != 0:
        with open(output_file, 'w') as file:
            file.write(f'''
Binary: {filepath[11:]}
Program Exited with: {code} | {get_signal(code)}
Number of Paths Found: {num_paths}
Total time Taken: {ptime}''')
            file.close()
        if isinstance(payload, bytes):
            bad = './fuzzer_output/bad_' + filepath[11:] + '.txt'
            with open(bad, 'wb') as badfile:
                badfile.write(payload)
                badfile.close()
        else:
            bad = './fuzzer_output/bad_' + filepath[11:] + '.txt'
            with open(bad, 'w') as badfile:
                badfile.write(payload)
                badfile.close()
    else:
        with open(output_file, 'w') as file:
            file.write(f'''
Binary: {filepath[11:]}
Program Exited with: Normal Exit (No Crash)
Number of Paths Found: {num_paths}
Total time Taken: {ptime}''')
            file.close()
'''
Returns a string about which signal was received that wasnt 0
'''
def get_signal(code):
    if code == signal.SIGABRT: return "SIGABRT - abort() Call"
    elif code == signal.SIGALRM: return "SIGALRM - alarm() Call"
    elif code == signal.SIGBUS: return "SIGBUS - Bus Error (Bad Memory Access)"
    elif code == signal.SIGCHLD: return "SIGCHLD - Child Process Terminated"
    elif code == signal.SIGFPE: return "SIGFPE - Floating Point Exception"
    elif code == signal.SIGHUP: return "SIGHUP - Hangup Detected on Controlling Terminal or Death of Controlling Process"
    elif code == signal.SIGILL: return "SIGILL - Illegal Instruction"
    elif code == signal.SIGINT: return "SIGINT - Interrupt from Keyboard (CTRL + C)"
    elif code == signal.SIGKILL: return "SIGKILL - Kill Signal"
    elif code == signal.SIGPIPE: return "SIGPIPE - Broken Pipe"
    elif code == signal.SIGSEGV: return "SIGSEGV - Segfault Detected (Invalid Memory Reference.)"
    elif code == signal.SIGTERM: return "SIGTERM - Termination Signal"
    elif code == signal.SIGUSR1: return "SIGUSR1 - User Defined Signal (Unknown)"
    elif code == signal.SIGUSR2: return "SIGUSR2 - User Defined Signal (Unknown)"
    else: return "Unknown Signal Received"

'''
Checks whether a string match occurs within the first n chars to scan for duplicate outputs
'''
def check_start_output(o, paths):
    if len(o) == 0: return False
    length = 10 if len(o) > 10 else len(o) / 2
    for path in paths:
        if isinstance(o, bytes):
            if o[:length] in path:
                return True
        else:
            if o[:length].encode() in path:
                return True
    return False