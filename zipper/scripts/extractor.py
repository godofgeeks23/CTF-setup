import os
import zipfile

def extract_zip_file(file_path):
    if file_path.endswith(".txt"):
        return

    with zipfile.ZipFile(file_path, 'r') as zip_obj:
        zip_obj.extractall()
        new_file_path = zip_obj.namelist()[0]

    os.remove(file_path)
    extract_zip_file(new_file_path)

extract_zip_file("IFUPS.zip")
