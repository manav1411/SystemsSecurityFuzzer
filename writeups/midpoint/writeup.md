# Documentation
## Team FuzzForce
### Jerry Yang (z5421983) | Manav Dodia (z5417834) | Jasmin Wu (z5482839) | Isabelle Dwyer (z5413928)

Mutation strategies used
1) After parsing the format of the given sample input (json, csv, etc.) we're manipulating the data by adding and then removing fields at random. We're also sending correctly formatted data with fuzzed fields such as replacing numerical fields with max/min integers, replacing strings with very large strings, empty strings, "%p" (to test for format string vuln), etc. 

2) We're also manipulating the sample input more randomly by just flipping bits and sending that to the binary.


Harness:
Currently, we're using a very simple harness that just:
a) Runs each binary repeatedly with the various fuzzed test cases given.
b) Checks the return code after executing the program in order to detect if the given input causes a crash.
c) Upon detecting a crash, it will write the bad input to fuzzer_output as required in the spec.

What bugs our fuzzer can find:
- Buffer overflows (caused a 'stack smashing' error message in csv1)
- Integer overflows (segfault caused by a large positive integer in the len field of json1)

Improvements that can/will be made:
Fuzzer:
- Expand our fuzzer techniques to parse and manipulate other input types beyond json and csv.
- Add byte flipping

Harness:
- Instead of simply checking the exit code or waiting for a hang, we also want to expand the analytics part of our harness so it can detect things like early exits due to sanitisation checks (e.g. stack smashing), error messages, or weird memory states. We'll look into using gdb for this.
- Attaching gdb to our harness to allow us to narrow down what type of vulnerability we've found and thus refine our bad input so it's as simple as possible.
- We also want to add some code coverage functionality, so that we can determine whether our fuzzed test cases are touching on as many code paths as possible. This is important as it will help avoid the issue of wasting time running 100s of fuzzed inputs that only follow one code path.
- Instead of running the program each time for each new input which is time-consuming, we want to save the initial state of the program's memory, and then on a crash or just before exiting cleanly, we can reset memory to what it was in initial state and keep running.
