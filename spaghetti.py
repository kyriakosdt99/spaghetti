import random
import math
import sys
import re
import os

from tqdm import tqdm
from z3 import *

def read_code():
    global code
    global file_path
    with open(file_path, 'r') as file:
        code = file.read()
        file.close()

def write_code():
    global code
    global output_file_path
    with open(output_file_path, 'w') as file:
        file.write(code)
        file.close()

def remove_comments():

    global code

    code_lines = code.split('\n')

    # Remove single-line comments and blank lines after stripping
    code_lines = [line for line in code_lines if not line.strip().startswith('#') and line.strip()]

    # Combine lines back into a single string
    modified_code = "\n".join(code_lines)

    # This regex will remove simple block comments, but may not handle nested quotes correctly
    modified_code = re.sub(r'(\'\'\'[\s\S]*?\'\'\'|\"\"\"[\s\S]*?\"\"\")', '', modified_code, flags=re.MULTILINE)

    code = ''.join(modified_code)


def code_to_xor_eval():
    
    global code

    key = os.urandom(len(code))

    xor_encrypted_code = [ord(c) ^ k for c, k in zip(code, key)]

    xor_encrypted_code_string = '['+','.join(f"({_})" for _ in xor_encrypted_code)+']'

    key_string = '['+','.join(f"({_})" for _ in key)+']'

    modified_code = f"exec(''.join([chr(c ^ k) for c, k in zip({xor_encrypted_code_string}, {key_string})]))"

    code = modified_code

def find_xor_values(num):
    a = BitVec('a', 32)
    b = BitVec('b', 32)
    solver = Solver()
    solver.add(a ^ b == num)
    solver.add(a == random.randint(2**18, 2**32))
    solver.add(a != 0)
    solver.add(b != 0)
    if solver.check() == sat:
        model = solver.model()
        return model[a].as_long(), model[b].as_long()
    else:
        raise ValueError("No solution found for XOR values.")

def replace_with_xor(code, match, a, b):
    return code[:match.start(1)] + f"({a}) ^ ({b})" + code[match.end()-1:]

def num_to_xor_a_b():
    
    global code

    # Define the pattern for matching an integer from 0 to 255 in the form [:space:]num[:comma:]
    pattern = r'[\(\[](\d+)[\)\]]'

    # Find all occurrences of the pattern in the text
    occurrences = re.finditer(pattern, code)

    # Convert matches to a list for easy random selection
    occurrences_list = list(occurrences)

    if occurrences_list:
        # Choose a random match
        random_occurrence = random.choice(occurrences_list)

        # Extract the matched integer
        matched_integer = int(random_occurrence.group(1))

        if matched_integer == 256:
            return

        # Find XOR values using Z3 solver
        try:
            a, b = find_xor_values(matched_integer)
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Replace the integer
        modified_code = replace_with_xor(code, random_occurrence, a, b)

        code = modified_code

def num_to_inline_if_else():
    
    global code

    pattern = r'\((\d+)\)'

    # Find all occurrences of the pattern in the text
    occurrences = re.finditer(pattern, code)

    # Convert matches to a list for easy random selection
    occurrences_list = list(occurrences)

    if occurrences_list:
        # Choose a random match
        random_occurrence = random.choice(occurrences_list)

        # Extract the matched integer
        matched_integer = int(random_occurrence.group(1))

        # Define Z3 variables
        a = BitVec('a', 64)
        b = BitVec('b', 64)

        constraint = (a>>23 & b<<17) == 0

        # Create a Z3 solver
        solver = Solver()
        solver.add(constraint)
        solver.add(a == random.randint(2**18, 2**32))
        solver.add(b != 0)

        # Check if there is a solution
        if solver.check() == sat:
            model = solver.model()
            value_a = model[a].as_long()
            value_b = model[b].as_long()

        # Replace the integer occurrence
        new_code = f"({matched_integer}) if (({value_a})>>(17) & ({value_b})<<(23)) == (0) else ({value_a^value_b})"

        modified_code = code[:random_occurrence.start(1)] + new_code + code[random_occurrence.end()-1:]

        code = modified_code

def num_to_inline_if_else_neg():
    
    global code

    pattern = r'\((\d+)\)'

    # Find all occurrences of the pattern in the text
    occurrences = re.finditer(pattern, code)

    # Convert matches to a list for easy random selection
    occurrences_list = list(occurrences)

    if occurrences_list:
        # Choose a random match
        random_occurrence = random.choice(occurrences_list)

        # Extract the matched integer
        matched_integer = int(random_occurrence.group(1))

        # Define Z3 variables
        a = BitVec('a', 64)
        b = BitVec('b', 64)

        constraint = (a>>3 & b<<13) != 0

        # Create a Z3 solver
        solver = Solver()
        solver.add(constraint)
        solver.add(a == random.randint(2**18, 2**32))
        solver.add(b != 0)

        # Check if there is a solution
        if solver.check() == sat:
            model = solver.model()
            value_a = model[a].as_long()
            value_b = model[b].as_long()

        # Replace the integer occurrence
        new_code = f"({value_a^value_b}) if (({value_a})>>(3) & ({value_b})<<(13)) == (0) else ({matched_integer})"

        modified_code = code[:random_occurrence.start(1)] + new_code + code[random_occurrence.end()-1:]

        code = modified_code


def main():

    global file_path
    global output_file_path
    global code

    if len(sys.argv) <= 2:
        print(f"Usage: {sys.argv[0]} \x7binput_file\x7d \x7boutput_file\x7d")
        exit()

    file_path = sys.argv[1]
    output_file_path = sys.argv[2]
    code = ''

    read_code()

    remove_comments()
    code_to_xor_eval()

    iterations = int(math.sqrt(len(code)))
    try:
        with tqdm(total=iterations, desc="Obfuscating... ") as pbar:
            for _ in range(iterations):
                num_to_xor_a_b()
                num_to_inline_if_else()
                num_to_inline_if_else_neg()
                pbar.update(1)
    except KeyboardInterrupt:
        print("\rExiting...",end="")
        sys.stdout.flush()
        exit()

    write_code()

    exit()

if __name__ == "__main__":
    main()