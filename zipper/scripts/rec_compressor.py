import os
import zipfile
import random
import string

def generate_random_string():
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(5))

def zip_file(file_path, count=597):
    if count == 0:
        return

    new_file_path = generate_random_string() + ".zip"
    with zipfile.ZipFile(new_file_path, 'w') as zip_obj:
        zip_obj.write(file_path)
        print("created file: " + new_file_path)

    if count > 1:
        os.remove(file_path)

    zip_file(new_file_path, count-1)

zip_file("challenge_message.txt")
