import hashlib
import base64

def url_format(data: bytes) -> str:
    """
    Convert a bytes sequence to its URL-encoded representation by percent-encoding each byte.

    Each byte in the input is formatted as a two-digit hexadecimal number,
    prefixed with '%', as commonly used in URL encoding.

    Args:
        data (bytes): The input data to encode.

    Returns:
        str: A string where each byte of `data` is represented as '%XX',
             with XX being the lowercase hexadecimal value of the byte.

    Example:
        >>> url_format(b'Hello!')
        '%48%65%6c%6c%6f%21'
    """
    return ''.join(f'%{byte:02x}' for byte in data)
    

def compute_hash(algorithm = 'md5', 
		message, 
		output_format = 'bytes'):
    '''
    
    Parameters
    ----------
    algorithm : str
        Must be one of the following algorithms: 
	    1. 'md5'
	    2. 'sha256'
	    3. 'sha512'
	
	    Otherwise throws an error. 
    message : bytes (or bytes-like object)
        Encoded message to be hashed with the given algorithm. 
	output_format : str
		Must be one of the following: 
		i. 'bytes'
	    ii. 'hex'
		iii. base64

		Otherwise throws an error
		
    Returns
    -------
	The hash digest of message, using the given algorithm, in the given format. If 'bytes', will return a bytes object. If 'hex' or 'base64' will return a string of the given encoding. 
    '''
    algorithms = {'md5', 'sha256', 'sha512'}
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported algorithm")

    hash_func = getattr(hashlib, algorithm)
    hasher = hash_func()
    hasher.update(message)
    digest_binary = hasher.digest() 
    digest_hex=hasher.hexdigest()

    # Format output
    if output_format == 'bytes':
        return digest_binary
    elif output_format == 'hex':
        return digest_hex
    elif output_format == 'base64':
        return base64.b64encode(digest).decode('ascii')
    else:
        raise ValueError("Invalid output_format")


def compute_padding( algorithm: str = 'md5',
         output_format: str = 'bytes', 
         message: bytes = None,
        ):
    """
    Parameters
    ----------
    algorithm : str
        One of: 'md5', 'sha256', 'sha512'
    message : bytes
        Data to hash. Required.
    output_format : str
        One of: 'bytes', 'hex', 'base64'
    
    Returns
    -------
    bytes or str
        The padding that the given algorithm adds to the message before processing. To be used in implementation of the length extension attack. 
    """
