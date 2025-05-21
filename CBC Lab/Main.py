from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def pad_msg(msg: bytes) -> bytes:
    '''
    PKCS#7 pads the message for AES (block size of 16)
    '''
    length=len(msg)
    pad_length=16-(length%16)
    padding = bytes([pad_length] * pad_length)
    return msg + padding
    

def check_padding(padded_msg: bytes) -> bool:
    '''
    Verifies that the input is PKCS#7 padded

    '''
    if not padded_msg:
        return False

    padding_len = padded_msg[-1]  # Last byte tells us how much padding
    if padding_len == 0 or padding_len > 16:
        return False
    
    padding = padded_msg[-padding_len:]
    for byte in padding:
        if byte != padding_len:
            return False
    
    return True
    
def unpad_msg(padded_msg: bytes) -> bytes:
    '''
    Strips the padding if it is valid, raises an exception if not.
    '''
    if not check_padding(padded_msg):
        return padded_msg  # or raise ValueError("Invalid padding")
    
    padding_len = padded_msg[-1]
    return padded_msg[:-padding_len]

class AESCBCCipher:
    def __init__(self, block_decryptor):
        self.block_decrypt = block_decryptor

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypts `ciphertext` under CBC mode.
        The IV is assumed to be the first 16 bytes of the ciphertext.
        The plaintext may contain padding
        """
        if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
            raise ValueError("Invalid Ciphertext")

        iv = ciphertext[:16]
        blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]

        plaintext = b""
        previous = iv

        for block in blocks:
            decrypted = self.block_decrypt(block)        
            xored = bytes(a ^ b for a, b in zip(decrypted, previous))  
            plaintext += xored
            previous = block 
            
        return unpad_msg(plaintext)

def aes_block_decrypt(key: bytes, block: bytes) -> bytes:
    """
    Decrypt exactly one 16-byte block under AES-ECB.
    
    Parameters
    ----------
    key : bytes
    16, 24, or 32-byte AES key
    block : bytes
    16-byte ciphertext block
    
    Returns
    -------
    bytes
    16-byte plaintext block
    """
    if len(block) != AES.block_size:
        raise ValueError(f"Ciphertexttext block must be {AES.block_size}bytes")
    if len(key) not in {16, 24, 32}:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def aes_cbc_encrypt(key: bytes, message: bytes) -> bytes:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message, AES.block_size))

def test_cbc():
    key = bytes(16)
    messages = [b"a sample message that's more than a block", b"a sample message", b"short"]
    decryptor = (lambda block: aes_block_decrypt(key, block))
    cbc_cipher = AESCBCCipher(decryptor)
    for m in messages:
        ctxt = aes_cbc_encrypt(key, m)
        assert cbc_cipher.decrypt(ctxt) == m
    print("All assertions passed!")
    
    
