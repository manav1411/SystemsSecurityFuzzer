import fuzz_main
from utils import print_line
import sys
import multiprocessing
from os import listdir
from os.path import isfile, join

programs = []

MAX_CORES = 4

if __name__ == "__main__":
    if len(sys.argv) == 3:
        print(f"Fuzzing: {sys.argv[1]}")
        print_line()
        fuzz_main.fuzz(sys.argv[1], sys.argv[2])

    elif len(sys.argv) != 3:
        print("No arguments given. Fuzzing all Binaries")
        print("For individual files use: python3 fuzzer.py [binaryname] [sampleinput.txt]")
        print_line()

        binaries = [f for f in listdir("./binaries") if isfile(join("./binaries", f))]
        print(binaries)

        for i in range(0, len(binaries)):
            #fuzz_main.fuzz(binaries[i], binaries[i] + ".txt")
            programs.append(multiprocessing.Process(target=fuzz_main.fuzz, args=(binaries[i], binaries[i] + ".txt")))

        while len(programs) > 0 or active_children:
            active_children = len(multiprocessing.active_children())
            if active_children >= MAX_CORES:
                continue
            if len(programs) > 0:
                run = programs.pop()
                run.start()