import subprocess
import time
import os

files_to_transfer = [
    (r"C:\Users\HP\Desktop\logsentry\api.py", "kali@192.168.1.3:~/Desktop/logsentry/api.py"),
    (r"C:\Users\HP\Desktop\logsentry\attack_simulation_test.py", "kali@192.168.1.3:~/Desktop/logsentry/attack_simulation_test.py"),
    (r"C:\Users\HP\Desktop\logsentry\src\alert_store.py", "kali@192.168.1.3:~/Desktop/logsentry/src/alert_store.py"),
    (r"C:\Users\HP\Desktop\logsentry\src\feature_extractor.py", "kali@192.168.1.3:~/Desktop/logsentry/src/feature_extractor.py"),
    (r"C:\Users\HP\Desktop\logsentry\data\signatures.json", "kali@192.168.1.3:~/Desktop/logsentry/data/signatures.json")
]

def main():
    success_count = 0
    for local, remote in files_to_transfer:
        if not os.path.exists(local):
            print(f"Error: Local file {local} does not exist. Skipping.")
            continue
            
        print(f"Transferring {os.path.basename(local)}...")
        # Use OpenSSH scp command with strict host key checking disabled
        cmd = ["scp", "-o", "StrictHostKeyChecking=no", local, remote]
        
        # Popen to run asynchronously and pipe stdin
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Wait a moment for the password prompt
        time.sleep(1.5)
        
        try:
            # Send password
            p.stdin.write("kali\n")
            p.stdin.flush()
        except Exception as e:
            print(f"Error piping password: {e}")
            
        # Complete execution and collect output
        stdout, stderr = p.communicate()
        
        if p.returncode == 0:
            print(f"Successfully transferred {os.path.basename(local)}!")
            success_count += 1
        else:
            print(f"Failed to transfer {os.path.basename(local)} (Exit code: {p.returncode})")
            print(f"STDERR: {stderr}")
            print(f"STDOUT: {stdout}")
            
    print(f"\nFinished. Successfully transferred {success_count}/{len(files_to_transfer)} files.")

if __name__ == "__main__":
    main()
