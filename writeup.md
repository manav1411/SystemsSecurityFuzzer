# Documentation
## Team FuzzForce
### Jerry Yang (z5421983) | Manav Dodia (z5417834) | Jasmin Wu (z5482839) | Isabelle Dwyer (z5413928)

Your fuzzer design and functionality (around 1-2 pages)

This section should explain, in a readable manner:

How your fuzzer works. Detailed description on;
The different mutation strategies you use.

How your harness works.

All of your fuzzers' capabilities
What kinds of bugs your fuzzer can find
What improvements can be made to your fuzzer (Be honest. We won't dock marks for things you didn't implement. This shows reflection and understanding)
If you attempt any bonus marks - How your fuzzer achieves these bonus marks.
It is insufficient if the document merely states "our fuzzer injects random values and finds bugs". We want details that show deep understanding.

### CHECKLIST (REMOVE BEFORE SUBMISSION)

General Fuzzer (10 marks)
[5] Finding all vulnerabilities in the 11 provided binaries and all hidden binaries.
[5] Writing test vulnerable binaries to test your fuzzer

## Fuzzer functionality (10 marks)
[5] Mutation Strategies
- Basic (bit flips, byte flips, known ints)
- Intermediate (repeated parts, keyword extraction, arithmetic)
- Advanced (coverage based mutations)
[5] Understanding & manipulating file formats (file headers/names, data structures, etc)
- Basic (JSON, CSV, XML)
- Intermediate (JPEG, ELF)
- Advanced (PDF)

## Harness Functionality (10 marks)
[2] Detecting the type of crash
[2] Detecting Code Coverage
[2] Avoiding overheads
- Not creating files
- In memory resetting (Not calling execve)
[2] Useful logging / statistics collection and display
[2] Detecting Hangs / Infinite loops
- Detecting infinite loop (code coverage) vs slow running program (timeout approach)

## Documentation (10 marks)
The documentation/writeup for the final fuzzer is worth 10 marks. Marks are awarded based on detail and conciseness of your writeup.