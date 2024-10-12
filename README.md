# SystemsSecurityFuzzer
A black-box fuzzer for binaries

Fuzzer is in `fuzzer.py`



## basic test case

`test.c`: basic C program that outputs user input

```gcc test.c -o test```: [optional] to compile.

`test`: executable for above C file.

`test.txt`: valid input for above C file.



`python3 fuzzer.py -f test -i test.txt`: runs fuzzer