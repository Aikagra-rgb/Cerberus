import os

# Get the base directory (The LOGSENTRY folder)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR = os.path.join(DATA_DIR)  # Where demo_access.log lives

# Specific Files
DATASET_PATH = os.path.join(DATA_DIR, 'cic_thursday.csv')
MODEL_PATH = os.path.join(MODELS_DIR, 'web_classifier.pkl')
SIGNATURES_PATH = os.path.join(DATA_DIR, 'signatures.json')
DB_PATH = os.path.join(BASE_DIR, 'sentinel.db')

# ==============================================================
# UNIFIED AI FEATURE SET
# All Random Forest models use the SAME 20 features.
# These are the CIC-IDS2017 column names from the CSV files.
# ==============================================================
UNIFIED_FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Min',
    'Fwd IAT Mean',
    'Fwd IAT Min',
    'SYN Flag Count',
    'RST Flag Count',
    'Init_Win_bytes_forward',
]

# Short parameter keys for simulation log lines.
# Order MUST match UNIFIED_FEATURES exactly (1-to-1 positional mapping).
FEATURE_SHORT_KEYS = [
    'dport',        # Destination Port
    'dur',          # Flow Duration
    'fpkts',        # Total Fwd Packets
    'bpkts',        # Total Backward Packets
    'fwd_len',      # Total Length of Fwd Packets
    'bwd_len',      # Total Length of Bwd Packets
    'fwd_max',      # Fwd Packet Length Max
    'fwd_pkt_mean', # Fwd Packet Length Mean
    'bwd_max',      # Bwd Packet Length Max
    'bwd_pkt_mean', # Bwd Packet Length Mean
    'byte_rate',    # Flow Bytes/s
    'pkt_rate',     # Flow Packets/s
    'iat_mean',     # Flow IAT Mean
    'iat_std',      # Flow IAT Std
    'iat_min',      # Flow IAT Min
    'fwd_iat_mean', # Fwd IAT Mean
    'fwd_iat_min',  # Fwd IAT Min
    'syn_cnt',      # SYN Flag Count
    'rst_cnt',      # RST Flag Count
    'init_win_fwd', # Init_Win_bytes_forward
]

# Legacy setting, kept for backward compatibility
CONTAMINATION_RATE = 0.01

# ==============================================================
# MODEL CONFIGURATIONS
# Each model trains on a specific CIC-IDS2017 CSV.
# All models use the same UNIFIED_FEATURES (20 columns).
# Attack detection uses "not BENIGN" logic to avoid label encoding issues.
# ==============================================================
MODEL_CONFIGS = {
    "web": {
        "filename": "cic_thursday.csv",
        "description": "Web Attacks (SQLi, XSS, Brute Force) — Thursday",
    },
    "auth": {
        "filename": "cic_tuesday.csv",
        "description": "Brute Force Login (SSH/FTP Patator) — Tuesday",
    },
    "dos": {
        "filename": "cic_wednesday.csv",
        "description": "DoS/DDoS (Hulk, GoldenEye, Slowloris) — Wednesday",
    },
    "recon": {
        "filename": "cic_friday_portscan.csv",
        "description": "Port Scanning / Reconnaissance — Friday",
    },
    "ddos": {
        "filename": "cic_friday_ddos.csv",
        "description": "DDoS LOIC Flood — Friday",
    },
    "botnet": {
        "filename": "cic_friday_morning.csv",
        "description": "Botnet C2 Beacons (Ares) — Friday Morning",
    },
    "infiltration": {
        "filename": "cic_thursday_infiltration.csv",
        "description": "Lateral Movement / Exfiltration — Thursday",
    },
}