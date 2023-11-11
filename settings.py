# AES CBC encoding settings
# TODO: If you want to randomise key and IV 
# key = get_random_bytes(16)  # 128-bit AES key
# iv = get_random_bytes(16)   # Initialization Vector

BLOCK_SIZE = 128
NUM_BYTES = BLOCK_SIZE//8

key = '0123456789abcdef'
IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
atk_block = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01'