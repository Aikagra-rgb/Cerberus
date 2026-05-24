#!/bin/bash
echo "[*] Starting Cyber Attack Simulation..."

echo "[+] Launching SQL Injection..."
echo "2025-11-21 12:00:01 - UNION SELECT user,pass FROM users - From 45.33.22.11" >> demo_access.log
sleep 2

echo "[+] Launching XSS Attack..."
echo '2025-11-21 12:00:05 - GET /search?q=<script>alert(1)</script> - From 203.0.113.5' >> demo_access.log
sleep 2

echo "[+] Launching Brute Force Wave..."
for i in {1..5}
do
   echo "Nov 21 12:00:1$i server sshd: Failed password for root from 185.200.10.1" >> demo_auth.log
   sleep 1
done

echo "[+] Tampering with System Files..."
echo "backdoor_active=1" >> critical_config.conf

echo "[*] Simulation Complete."