import os
import sys
import sqlite3

# Import sdk directly to load libraries only once (prevents crashes)
try:
    import sdk
except ImportError:
    print("Error: sdk.py not found in the current directory.")
    sys.exit(1)

# --- CONFIGURATION ---
directories = [
    { "path": r"D:\datas2\data2", "label": 0 },          # Benign
    { "path": r"D:\datas2\datamaliciousorder", "label": 1 } # Malicious
]
DB_PATH = 'signatures.db'
# ---------------------

def is_already_in_db(db_path, file_md5):
    """Check DB for hash manually to avoid wasting time extracting features for duplicates."""
    if not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT md5 FROM samples WHERE md5 = ?', (file_md5,))
        exists = c.fetchone()
        conn.close()
        return exists is not None
    except Exception:
        return False

def main():
    # Initialize the feature extractor once
    print("Loading AI engines (this takes a moment)...")
    fe = sdk.FeatureExtractor()
    db = sdk.SignatureDB(DB_PATH)
    
    total_added = 0
    
    for entry in directories:
        folder_path = entry["path"]
        label = entry["label"]
        
        if not os.path.exists(folder_path):
            print(f"Skipping missing directory: {folder_path}")
            continue
            
        print(f"\n--- Processing {folder_path} with Label {label} ---")
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip non-executable files to avoid errors
                if not file.lower().endswith(('.exe', '.dll', '.sys', '.pyd')):
                    continue

                try:
                    # 1. Check MD5 first (fastest)
                    current_md5 = sdk.md5_file(file_path)
                    
                    if is_already_in_db(DB_PATH, current_md5):
                        # print(f"Skipping duplicate: {file}") # Uncomment to see skips
                        continue

                    # 2. Extract features (slower)
                    print(f"Analyzing: {file}...", end="\r")
                    analysis, features = fe.extract(file_path)
                    
                    # 3. Add to DB
                    db.add_sample(file_path, label, features, analysis)
                    total_added += 1
                    
                except KeyboardInterrupt:
                    print("\n[!] Process interrupted by user.")
                    sys.exit(0)
                except Exception as e:
                    print(f"\n[!] Error analyzing {file}: {e}")

    print(f"\n\nDone! Added {total_added} new samples to {DB_PATH}.")

if __name__ == "__main__":
    main()
