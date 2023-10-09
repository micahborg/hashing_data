import hashlib

input_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\38650-password-sktorrent.txt"  # passwords file path
output_file_path = r"\Users\micah\OneDrive - University of Kansas\KU Junior\EECS 465\password_hashes_md5.txt"  # output file path

def compute_md5_hash(password): # compute the MD5 hash for a password
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    return md5.hexdigest()

try:
    with open(input_file_path, 'r') as input_file: # open the input file for reading passwords
        with open(output_file_path, 'w') as output_file: # open the output file for writing hashes
            for line in input_file:
                password = line.strip() # remove whitespace
                if password:
                    md5_hash = compute_md5_hash(password) # compute the MD5 hash for a password
                    output_file.write(md5_hash + '\n')
    
    print(f"Password hashes saved to {output_file_path}")
except FileNotFoundError:
    print(f"File '{input_file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {str(e)}")
