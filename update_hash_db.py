#!/usr/bin/env python3

import hashlib
import os


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

    return sha256.hexdigest()


def save_hashes_to_file(file_paths, output_path):
    with open(output_path, 'w') as output_file:
        for file_path in file_paths:
            if os.path.isfile(file_path):
                hash_value = calculate_sha256(file_path)
                if hash_value:
                    output_file.write(f"{hash_value}  {file_path}\n")
            else:
                print(f"File not found: {file_path}")


bin_paths = [
    "/bin/unhide",
    "/bin/rkhunter"
]

output_path = "__tmphashtable"

save_hashes_to_file(bin_paths, output_path)

