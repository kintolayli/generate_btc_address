import hashlib
import ecdsa
import base58


def generate_bitcoin_address():
    # Generate a random 256-bit ECDSA private key
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()

    # Perform SHA-256 hashing on the private key
    sha256_private = hashlib.sha256(private_key).digest()

    # Perform RIPEMD-160 hashing on the SHA-256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_private)
    ripemd160_hash = ripemd160.digest()

    # Add the network byte (0x00) to the beginning of the RIPEMD-160 hash
    prefix_ripemd160_hash = b'\x00' + ripemd160_hash

    # Perform SHA-256 hashing on the prefix + RIPEMD-160 hash
    sha256_ripemd160 = hashlib.sha256(prefix_ripemd160_hash).digest()

    # Perform SHA-256 hashing again on the SHA-256 hash
    double_sha256 = hashlib.sha256(sha256_ripemd160).digest()

    # Take the first 4 bytes of the double SHA-256 hash as the checksum
    checksum = double_sha256[:4]

    # Concatenate the prefix + RIPEMD-160 hash + checksum
    binary_address = prefix_ripemd160_hash + checksum

    # Convert the binary address to a Base58 string using Base58check encoding
    base58_address = base58.b58encode(binary_address).decode('utf-8')

    # Return the public address and private key
    return base58_address, int.from_bytes(private_key, byteorder='big')

print(generate_bitcoin_address())