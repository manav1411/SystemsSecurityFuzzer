import sys
import os

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 src/fuzzer.py [binaryname] [sampleinput.txt]")
        exit()

    os.system(f"python3 src/fuzzer.py {sys.argv[1]} {sys.argv[2]}")
