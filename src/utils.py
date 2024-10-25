from pwn import *

context.log_level='warn'

def write_crash_output(filename, input):
    output_file = './fuzzer_output/bad_' + filename[11:] + '.txt'
    with open(output_file, 'w') as file:
        file.write(input)
        file.close()
    print(f"Writing Input: ( {input} ) to Output File : ( {output_file} )")

def get_process(filepath):
    return process(filepath, timeout=1.5)

def print_crash_found():
    print("#########################################")
    print("######### Crashable Input Found #########")
    print("#########################################")

def print_no_crash_found():
    print("#########################################")
    print("####### No Crashable  Input Found #######")
    print("#########################################")


'''
Checks whether a given data is an int
'''
def is_num(data):
    return isinstance(data, int)

'''
Checks whether a given data is a str
'''
def is_str(data):
    return isinstance(data, str)
