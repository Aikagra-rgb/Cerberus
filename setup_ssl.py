import os
import subprocess
import sys
import platform

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CRITICAL = "\033[91m"
RESET = "\033[0m"

print(f"{CYAN}==================================================================")
print("     LogSentry TLS/SSL Secure HTTPS Bootloader")
print(f"=================================================================={RESET}\n")

key_file = "server.key"
cert_file = "server.crt"

def generate_certificates():
    print(f"[*] Checking for existing SSL certificates...")
    if os.path.exists(key_file) and os.path.exists(cert_file):
        print(f"[{GREEN}+{RESET}] Active SSL certificate files found: '{key_file}' and '{cert_file}'.")
        return True
        
    print(f"[!] Certificates not found. Generating strong 4096-bit self-signed SSL/TLS credentials...")
    
    # 1. Attempt system openssl (cross-platform, native on Kali Linux)
    try:
        cmd = (
            f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} '
            '-days 365 -nodes -subj "/CN=localhost"'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and os.path.exists(key_file):
            print(f"[{GREEN}+{RESET}] Successfully generated self-signed TLS certificates using OpenSSL.")
            return True
    except Exception:
        pass

    # 2. Python cryptography module fallback
    try:
        from datetime import datetime, timedelta
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        print("[*] OpenSSL not found or failed. Falling back to python 'cryptography' module...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Write private key
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        print(f"[{GREEN}+{RESET}] Successfully generated self-signed TLS certificates using Python cryptography.")
        return True
    except ImportError:
        print(f"[{CRITICAL}ERROR{RESET}] Neither 'openssl' command line utility nor python 'cryptography' package is installed.")
        print("        Install openssl on your OS, or run: pip install cryptography")
        return False

if __name__ == "__main__":
    if generate_certificates():
        print(f"\n[{GREEN}BOOTING{RESET}] Launching FastAPI backend in secure {GREEN}HTTPS Mode{RESET} on port 8000...")
        
        # Start uvicorn securely with SSL configuration key/cert arguments
        cmd = [
            "python", "-m", "uvicorn", "api:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--ssl-keyfile", key_file,
            "--ssl-certfile", cert_file
        ]
        
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\n[*] Secure HTTPS server stopped.")
            sys.exit(0)
    else:
        print(f"[{CRITICAL}FAIL{RESET}] Failed to start secure HTTPS bootloader due to missing SSL generators.")
        sys.exit(1)
