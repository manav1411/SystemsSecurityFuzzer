import main
from utils import print_line
import sys
import threading
from os import listdir
from os.path import isfile, join

if __name__ == "__main__":
    if len(sys.argv) == 3:
        print(f"Fuzzing: {sys.argv[1]}")
        print_line()
        main.fuzz(sys.argv[1], sys.argv[2])

    elif len(sys.argv) != 3:
        print("No arguments given. Fuzzing all Binaries")
        print("For individual files use: python3 fuzzer.py [binaryname] [sampleinput.txt]")
        print_line()

        binaries = [f for f in listdir("./binaries") if isfile(join("./binaries", f))]

        for i in range(0, len(binaries)):
            main.fuzz(binaries[i], binaries[i] + ".txt")
            #t = threading.Thread(target=main.fuzz, args=(binaries[i], binaries[i] + ".txt"))
            #t.start()
            