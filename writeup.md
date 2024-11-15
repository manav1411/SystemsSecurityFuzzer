# Documentation
## Team FuzzForce
### Jerry Yang (z5421983) | Manav Dodia (z5417834) | Jasmin Wu (z5482839) | Isabelle Dwyer (z5413928)


## Fuzzer Functionality 
### Overview
Our fuzzer first determines what type of input file the binary accepts (e.g. CSV, XML, PDF) and then
runs a number of mutation strategies (detailed below) based on the input file type to try and cause
the program to either crash or hang. 

Our fuzzer can find bugs in the following 6 input types: Plaintext, JSON, CSV, XML, JPEG, ELF, PDF.

### Type of Bugs Found
- Format string vulnerabilities
- Integer overflows
- Buffer overflows
- Input validation failure (e.g. not checking if the input file is actually the correct format, or not checking whether the user input really is numeric/string/etc. before using it)


### General Mutation Strategies
These are the general mutation strategies we've used regardless of the input file format:
- Flipping a random number of bits of the valid input at a time
- Sequentially flip bits of the valid input file
- Inserting, removing, and changing random bytes of the valid input file
- Sequentially inserting dangerous bytes into hte valid input file
- Replacing numeric inputs with known dangerous ints listed in wordlists/allnumber.txt such as 0, 1, max and min integer values for signed/unsigned 8-bit, 16-bit, 32-bit, 64-bit integers, etc.
- Similarly, replacing string input with known dangerous strings listed in wordlists/naughtystrings.txt such as "", extremely long strings, format string specifiers such as "%s %s %s", etc.
- Swapping types: e.g. replacing numeric input with string inputs and visa versa. As well as changing types to others including arrays, objects, and booleans.


### Format-specific Mutation Strategies
- Malformed input: What is considered malformed obviously depends on the input type but an example would be removing the closing tag in XML file, changing the delimiters within CSV files.
- Adding fields: What counts as a field depends on the input type (e.g. Elements for XML, symbols for ELF, key-value pairs for JSON), but the basic idea is to duplicate an increasing number of fields (e.g. 10, 100, 2000 duplicates) so the input file is increasingly large.
- Removing fields: Similarly to above, our fuzzer removes particular fields one at a time, and then also also removes them cumulatively (until the input file becomes empty).
- Keyword extraction: For XML, JSON input files, our fuzzer searches for particular pre-defined keywords such as "admin", "length", etc. among the keys (JSON) or element/attribute names (XML) and alters the associated values (e.g. changing True to False, 0 to 1, etc.).


### Fuzzer Improvements
- Implement code-coverage based mutation strategies as our fuzzer currently doesn't do this at all. This would be a major improvement as it would help avoid the issue of wasting time running 100s of fuzzed inputs that only follow one code path.

## Harness functionality
Our harness:
- Runs each binary repeatedly with the various fuzzed test cases given using the subprocess module with multithreading enabled to speed up processing. Each binary is fuzzed for a maximum of 60 seconds.
- While it runs, the harness monitors code coverage by tracking when different program outputs
are produced. The number of different program outputs are used as an approximation of the number of different code paths the fuzzed test cases are touching.
- Checks the return code after executing the program in order to detect if the given input causes a crash. 
- Upon detecting a crash, it will write the bad input to fuzzer_output as required in the spec.
- Regardless of whether the program crashes or not, the harness will also log the following statistics about the binary fuzzed: time taken, number of different outputs detected, return code number, return code definition (e.g. "SIGSEGV - Segfault Detected (Invalid Memory Reference.)").


### Harness Improvements
- Implement the detection of hangs
- Avoid syscall overhead by employing memory resetting instead of using the subprocess module as we do now which reruns the program for every fuzzed input (time-consuming). This would require saving the initial state of the program's memory before input is given, and then after the program exits (either cleanly or due to a crash), resetting the memory to what it was in the initial state and provide a different fuzzed input.
- While it would noticeably slow down the fuzzer, attaching gdb to our harness would provide a better monitor for code coverage than our current strategy of tracking stdout output (e.g. by tracking what functions are being called and in what order). 
- Using gdb could also enable us to discover if the fuzzed input were causing an atypical memory state (by tracking function arguments) as opposed to relying on the exit code to discover bugs. For example, in the Wk9 challenge "abs" there's an integer overflow bug that our fuzzer wouldn't be able to detect because the program still exits normally even though it gives the wrong output.
