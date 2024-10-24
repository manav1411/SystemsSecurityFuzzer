# Documentation
## Team FuzzForce
### Jerry Yang (z5421983) | Manav Dodia (z5417834) | Jasmin Wu (z5482839) | Isabelle Dwyer (z5413928)

**Fuzzer design and functionality (around 1-2 pages)**


How your fuzzer works. Detailed description on;
The different mutation strategies you use.
How your harness works.
All of your fuzzers’ capabilities
What kinds of bugs your fuzzer can find


**CSV Fuzzer:**
The CSV Fuzzer is a fuzzer that generates random CSV files. The fuzzer uses a combination of mutation strategies to generate the CSV files.
- Malformed CSV file: This generates a CSV file that could have missing commas, missing values, or extra commas. This is done by randomly removing commas, adding commas, or removing values.

**Improvements:**
- Add more file formats to the fuzzer. This would allow the fuzzer to test more file formats and potentially find more bugs. We need to add support for text, XML and PDF.
- It would be good to test string format vulnerabilities and buffer overflows also.
