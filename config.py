# File size limit (smaller due to RSA limitations)
MAX_FILE_SIZE = 100 * 1024 * 1024 # 100MB

# Cryptographic settings
SALT_LENGTH = 16
KEY_ITERATION_COUNT = 100000
RSA_KEY_SIZE = 4096  # Increased for better security
RSA_PUBLIC_EXPONENT = 65537