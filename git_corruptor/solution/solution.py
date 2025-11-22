import zlib
import glob
import os

# Point this to the extracted .git/objects folder
OBJECTS_DIR = "git_ghost_challenge/.git/objects"

print(f"[*] Hunting for artifacts in {OBJECTS_DIR}...")

# Walk through all subdirectories (00-ff)
for root, dirs, files in os.walk(OBJECTS_DIR):
    for file in files:
        full_path = os.path.join(root, file)
        
        try:
            with open(full_path, "rb") as f:
                compressed_data = f.read()
                
            # Git objects are Zlib compressed
            decompressed = zlib.decompress(compressed_data)
            
            # Format: <type> <size>\0<content>
            # Example: blob 12\0Hello World
            
            if b"CTF{" in decompressed:
                print("\n[!!!] FLAG FOUND [!!!]")
                print(f"File: {full_path}")
                print("-" * 20)
                # Clean up the binary noise to show the text
                try:
                    text = decompressed.split(b'\0', 1)[1]
                    print(text.decode('utf-8', errors='ignore'))
                except:
                    print(decompressed)
                print("-" * 20)
                
        except Exception as e:
            # Not all files in objects are valid zlib blobs (though they should be)
            continue