# SystemsSecurityFuzzer
A black-box fuzzer for binaries

Fuzzer is in `fuzzer.py`



## Usage
Insert executable (`binary`) into /binaries

Insert valid input (`binary.txt`) into /example_inputs

To run only that binary: `python3 fuzzer.py binary binary.txt`

To run all binaries in the folder: `python3 fuzzer.py`
