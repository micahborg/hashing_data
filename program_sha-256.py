import hashlib

# Input and output file paths
input_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\38650-password-sktorrent.txt"  # passwords file path
output_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\password_hashes_sha256.txt"  # output file path

def compute_sha256_hash(password): # compute the SHA-256 hash for a password
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

try:
    with open(input_file_path, 'r') as input_file: # open the input file for reading passwords
        with open(output_file_path, 'w') as output_file: # open the output file for writing hashes
            for line in input_file:
                password = line.strip()  # remove whitespace
                if password:
                    sha256_hash = compute_sha256_hash(password) # compute the SHA-256 hash for a password
                    output_file.write(sha256_hash + '\n')
    
    print(f"SHA-256 hashes saved to {output_file_path}")
except FileNotFoundError:
    print(f"File '{input_file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {str(e)}")