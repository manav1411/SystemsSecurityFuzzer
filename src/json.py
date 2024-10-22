import json
from fuzzer import write_crash_output

# Hardcoded Values for Initial Mutation of Input
MASS_POS_NUM = 999999999999999999999999999999999999999999999999999999
MASS_NEG_NUM = -999999999999999999999999999999999999999999999999999999
OVERFLOW = "A" * 10000
BOUNDARY_MINUS = -1
BOUNDARY_PLUS = 1
ZERO = 0
ONE_BYTE = 128
TWO_BYTE = 32768
FOUR_BYTE = 2147483648
EIGHT_BYTE = 9223372036854775808
FORMAT = "%p"

# Returns whether the given data is valid JSON or not
def is_json(data):
    try:
        json.loads(data)
    except:
        return True
    
    return False

# Main to be called when fuzzing JSON
def fuzz_json(data):
    originaldata = data

    '''
    The second strategy is to concentrate on finding bugs after the document has been parsed/processed. In this case 
    we will aim to submit unexpected input but still stick to the format and the specifications of the document. This 
    strategy is used to discover a lot wider range of bugs depending on how the structured data is used later on inside 
    the application. The types of bugs discovered will depend on the targeted platform, language and all kinds of other 
    things.

    (MIN_INT, MAX_INT, UNSIGNED MAX_INT, LONG, etc). Unexpected input is also logical values such as true and false, 
    the special atom nil, null and 0 and 1.

    Try sending some known sample inputs (nothing, certain numbers, certain strings, etc)
    Try parsing the format of the input (normal text, json, etc) and send correctly formatted data with fuzzed fields.
    Try manipulating the sample input (bit flips, number replacement, etc)
    '''
    return 0

def add_fields(data: json, numfields):
    jsonData = json.load(data)
    for i in range(numfields):
        jsonData[f"RandomField{i}"] = f"RandomValue{i}"

    return jsonData
        

def remove_fields(data):
    return 0

def send_nothing(data):
    return 0