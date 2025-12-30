import os
from PIL import Image
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

# --- STEGANOGRAPHY (LSB) ---

def string_to_bin(data):
    """Convert string to binary string provided by utf-8"""
    return ''.join(format(ord(char), '08b') for char in data)

def bin_to_string(binary_data):
    """Convert binary string to utf-8 string"""
    data = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) < 8:
            break
        data.append(chr(int(byte, 2)))
    return ''.join(data)

def hide_data(image_path, secret_data, output_path):
    """
    Hides secret_data (string) into image_path using LSB.
    Saves the result to output_path.
    We append a delimiter '#####EOS#####' to know where to stop.
    """
    image = Image.open(image_path)
    # Convert to RGB to ensure we have 3 channels (skipping alpha for simplicity if present)
    image = image.convert("RGB") 
    
    secret_data += "#####EOS#####"
    binary_data = string_to_bin(secret_data)
    data_len = len(binary_data)
    
    pixels = list(image.getdata())
    new_pixels = []
    
    data_index = 0
    for pixel in pixels:
        if data_index < data_len:
            r, g, b = pixel
            
            # Modify LSB of Red channel
            if data_index < data_len:
                r = (r & ~1) | int(binary_data[data_index])
                data_index += 1
            
            # Modify LSB of Green channel
            if data_index < data_len:
                g = (g & ~1) | int(binary_data[data_index])
                data_index += 1
                
            # Modify LSB of Blue channel
            if data_index < data_len:
                b = (b & ~1) | int(binary_data[data_index])
                data_index += 1
                
            new_pixels.append((r, g, b))
        else:
            new_pixels.append(pixel)
            
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    new_image.save(output_path)
    print(f"Data hidden in {output_path}")

def extract_data(image_path):
    """
    Extracts hidden data from image_path.
    Stops when '#####EOS#####' is found.
    """
    image = Image.open(image_path)
    image = image.convert("RGB")
    pixels = list(image.getdata())
    
    binary_data = ""
    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)
        
    # Convert slightly more than needed chunks usually, but let's try to convert on the fly or just bulk
    # Optimization: Check for delimiter every byte could be slow, but safe.
    
    # Let's convert all binary to string (this is naive for large images but fine for this project)
    # Optimization: Just look for the binary pattern of the delimiter? 
    # Or just convert chunks.
    
    all_text = bin_to_string(binary_data)
    delimiter = "#####EOS#####"
    
    if delimiter in all_text:
        return all_text.split(delimiter)[0]
    else:
        # Fallback or error if delimiter not found (maybe image was not encoded)
        return ""

# --- ENCRYPTION (DES) ---

def adjust_key(key):
    """
    DES key must be 8 bytes. 
    If key is shorter, pad it. If longer, truncate it.
    """
    if len(key) < 8:
        return key.ljust(8) # Space padding
    return key[:8]

def encrypt_msg(plaintext, key):
    """
    Encrypts plaintext using DES with the given key (string).
    Returns hex string of ciphertext for easy transport.
    """
    des_key = adjust_key(key).encode('utf-8')
    cipher = DES.new(des_key, DES.MODE_ECB) # Using ECB as per typical simple assignments (or CBC if preferred, but ECB is simpler implementation-wise)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext.hex()

def decrypt_msg(ciphertext_hex, key):
    """
    Decrypts hex string ciphertext using DES with the given key.
    """
    try:
        des_key = adjust_key(key).encode('utf-8')
        cipher = DES.new(des_key, DES.MODE_ECB)
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, DES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"[Decryption Error]: {e}"

# --- TEST (If run directly) ---
if __name__ == "__main__":
    # Test Setup
    test_img = "test_base.png"
    if not os.path.exists(test_img):
        img = Image.new('RGB', (100, 100), color = 'red')
        img.save(test_img)
    
    print("--- Testing Steganography ---")
    secret = "MySecretPassword123"
    hide_data(test_img, secret, "test_encoded.png")
    extracted = extract_data("test_encoded.png")
    print(f"Original: {secret}")
    print(f"Extracted: {extracted}")
    assert secret == extracted
    
    print("\n--- Testing DES Encryption ---")
    msg = "Hello World!"
    key = "secretkey"
    enc = encrypt_msg(msg, key)
    print(f"Encrypted: {enc}")
    dec = decrypt_msg(enc, key)
    print(f"Decrypted: {dec}")
    assert msg == dec
    
    print("\nAll Tests Passed!")
