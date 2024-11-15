# Documentation
## Team FuzzForce
### Jerry Yang (z5421983) | Manav Dodia (z5417834) | Jasmin Wu (z5482839) | Isabelle Dwyer (z5413928)


## Fuzzer Functionality 
### Overview
Our fuzzer first determines what type of input file the binary accepts (e.g. CSV, XML, PDF) and then
runs a number of mutation strategies (detailed below) based on the input file type to try and cause
the program to either crash or hang.

### Type of Bugs Found
- Format string vulnerabilities
- Integer overflows
- Buffer overflows
- Input validation failure (i.e. not checking if the input file is actually the correct format)

[5] Mutation Strategies
- Basic (bit flips, byte flips, known ints)
- Intermediate (repeated parts, keyword extraction, arithmetic)
- Advanced (coverage based mutations)
[5] Understanding & manipulating file formats (file headers/names, data structures, etc)
- Basic (JSON, CSV, XML)
- Intermediate (JPEG, ELF)
- Advanced (PDF)

### General Mutation Strategies

### Format-specific Mutation Strategies

How your fuzzer works. Detailed description on;
The different mutation strategies you use.

### Fuzzer Improvements

## Harness functionality
Our harness:
a) Runs each binary repeatedly with the various fuzzed test cases given using the subprocess module with multithreading enabled to speed up processing. Each binary is fuzzed for a maximum of 60 seconds(IS THIS CORRECT?).
b) While it runs, the harness monitors code coverage by tracking when different program outputs
are produced. The number of different program outputs are used as an approximation of the number of different code paths the fuzzed test cases are touching.
c) Checks the return code after executing the program in order to detect if the given input causes a crash. 
### QUESTION: DOES OUR HARNESS DETECT HANGS? If so add that here as well
d) Upon detecting a crash, it will write the bad input to fuzzer_output as required in the spec.
e) Regardless of whether the program crashes or not, the harness will also log the following statistics about the binary fuzzed: time taken, number of different outputs detected, return code number, return code definition (e.g. "SIGSEGV - Segfault Detected (Invalid Memory Reference.)").


### Harness Improvements
- Avoid syscall overhead by employing memory resetting instead of using the subprocess module as we do now which reruns the program for every fuzzed input (time-consuming). This would require saving the initial state of the program's memory before input is given, and then after the program exits (either cleanly or due to a crash), resetting the memory to what it was in the initial state and provide a different fuzzed input.
- While it would noticeably slow down the fuzzer, attaching gdb to our harness would provide a better monitor for code coverage than our current strategy of tracking stdout output (e.g. by tracking what functions are being called and in what order). 
- Using gdb could also enable us to discover if the fuzzed input were causing an atypical memory state (by tracking function arguments) as opposed to relying on the exit code to discover bugs. For example, in the Wk9 challenge "abs" there's an integer overflow bug that our fuzzer wouldn't be able to detect because the program still exits normally even though it gives the wrong output.

### DELETE BEFORE SUBMISSION (REFERENCE ONLY)
[2] Detecting the type of crash
[2] Detecting Code Coverage
[2] Avoiding overheads
- Not creating files
- In memory resetting (Not calling execve)
[2] Useful logging / statistics collection and display
[2] Detecting Hangs / Infinite loops
- Detecting infinite loop (code coverage) vs slow running program (timeout approach)






