import sys
import os
from os import listdir
from os.path import isfile, join

if __name__ == "__main__":
    command = ""
    if len(sys.argv) != 3:
        print("No arguments given. Fuxzzing all Binaries")
        print("For individual files use: python3 fuzzer.py [binaryname] [sampleinput.txt]")
        binaries = [f for f in listdir("./binaries") if isfile(join("./binaries", f))]

        for file in binaries:
            command += f"python3 src/fuzzer.py {file} {file}.txt;"
    else:
        command = f"python3 src/fuzzer.py {sys.argv[1]} {sys.argv[2]}"

    os.system(command)
