import hashlib

# Input and output file paths
input_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\38650-password-sktorrent.txt"  # passwords file path
output_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\password_hashes_sha1.txt"  # output file path

try:
    with open(input_file_path, 'r') as input_file: # open the input file for reading passwords
        # Open the output file for writing hashes
        with open(output_file_path, 'w') as output_file: # open the output file for writing hashes
            for line in input_file:
                password = line.strip()  # remove whitespace
                if password:
                    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest() # compute the SHA-1 hash for the password
                    output_file.write(sha1_hash + '\n')
    
    print(f"SHA-1 hashes saved to {output_file_path}")
except FileNotFoundError:
    print(f"File '{input_file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {str(e)}")