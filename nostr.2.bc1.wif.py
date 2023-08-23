import hashlib
import hexlib
import bech32
from bech32 import bech32_encode, bech32_decode, convertbits
import base58
import ecdsa
import qrcode
#from PIL import Image

def private_key_to_public_key(private_key_hex):
    private_key_bytes = (private_key_hex)
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    return signing_key.get_verifying_key().to_string()

def generate_legacy_address(private_key_hex, compressed=False):
    public_key = private_key_to_public_key(private_key_hex)
    if compressed:
        public_key = compress_public_key(public_key)
    else:
        public_key = b'\x04' + public_key
    public_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
    version_byte_legacy = 0x00
    extended_hash = bytes([version_byte_legacy]) + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    address_bytes = extended_hash + checksum
    legacy_address = base58.b58encode(address_bytes).decode('utf-8')
    return legacy_address#, public_key

def generate_legacy_wif(private_key_bytes, compressed=False):
    extended_key = b'\x80' + private_key_bytes if not compressed else b'\x80' + private_key_bytes + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif_bytes = extended_key + checksum
    wif = base58.b58encode(wif_bytes).decode('utf-8')
    return wif

def compress_public_key(public_key):
    x = public_key[:32]
    y = public_key[32:]
    if y[-1] % 2 == 0:
        compressed_public_key = b'\x02' + x
    else:
        compressed_public_key = b'\x03' + x
    return compressed_public_key

def generate_keyhash(public_key):
    sha256_1 = hashlib.sha256(public_key)
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_1.digest())
    return ripemd160.digest()

def generate_Bech32_address(public_key):
    public_key=check_len_publichexkey(public_key)
    keyhash = generate_keyhash(public_key)
    native_bech32_address = bech32_encode('bc', [0] + convertbits(keyhash, 8, 5))
    return native_bech32_address

def check_len_publichexkey(public_key):
	if len(public_key) == 33:
		return public_key
	elif len(public_key) == 32:
		public_key = b'\x03' + public_key
		return public_key
	else:
		print("Invalid compressed public key length")

def bech32(key_str: str, hrp='npub'):
    as_int = [int(key_str[i:i+2], 16) for i in range(0, len(key_str), 2)]
    data = convertbits(as_int, 8, 5)
    return bech32_encode(hrp, data)

def convert_to_hex_key(npub_address):
    hrp , data = bech32_decode(npub_address)
    hex_pub_key = ''.join(format(byte, '02x') for byte in convertbits(data, 5, 8))
    return bytes.fromhex(hex_pub_key[:64])

def convert_to_npub(public_key, hrp='npub'):
	if hrp == 'npub':
		return bech32(public_key.hex())
	elif hrp == 'nsec':
		return bech32(public_key.hex(),'nsec')

def main():
    while True:
        print("This will convert NOSTR addresses to bitcoin")
        print("Menu:")
        print("1. Create BC1 Address from Public Key")
        print("2. Create BC1 Address and WIF from Private Key")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            user_input = input("Enter a public key or npub address: ")
            print("")
			
            if len(user_input) == 64:  # Assuming input is a public key
                user_input = bytes.fromhex(user_input)
                public_key=user_input
                npub_address = convert_to_npub(public_key)
            elif user_input.startswith("npub"):  # Assuming input is an npub address
                npub_address = user_input
                public_key = convert_to_hex_key(npub_address)
            else:
                print("Invalid input. Please enter a valid public key or npub address.")
                return
            
            # Convert public key to npub address
            converted_npub_address = convert_to_npub(public_key)
            print("Converted npub Address:", converted_npub_address)
            
            # Convert npub address back to compressed public key
            converted_pubkey = convert_to_hex_key(npub_address)
            print("Converted Public Key:", converted_pubkey.hex())
            
            # Generate Bech32 address
            native_bech32_address = generate_Bech32_address(converted_pubkey)
            print("Bitcoin Receive Address:", native_bech32_address)
            native_bech32_address_qr = qrcode.make(native_bech32_address)
            native_bech32_address_qr.save('from_publickey_native_bech32_address_qr.png')
        
        elif choice == '2':
            user_input = input("Enter a private hex key or nsec: ")
            print("")
			
            if len(user_input) == 64:  # Assuming input is a public key
                user_input = bytes.fromhex(user_input)
                private_key=user_input
                nsec_address = convert_to_npub(private_key,'nsec')
            elif user_input.startswith("nsec"):  # Assuming input is an npub address
                nsec_address = user_input
                private_key = convert_to_hex_key(nsec_address)
            else:
                print("Invalid input. Please enter a valid private key or nsec address.")
                return
            
            # Convert public key to npub address
            converted_nsec_address = convert_to_npub(private_key,'nsec') # change to nsec?
            #print("Converted nsec Address:", converted_nsec_address)
            
            # Convert npub address back to compressed public key
            converted_private_key = convert_to_hex_key(nsec_address)
            #print("converted_private_key Key:", converted_private_key.hex())
			
			
            private_key_bytes = converted_private_key.hex()
            private_key_hex	= converted_private_key	
			
            
            # Generate legacy addresses (both compressed and uncompressed)
            legacy_address_uncompressed = generate_legacy_address(private_key_hex)
            legacy_address_compressed = generate_legacy_address(private_key_hex, compressed=True)
            
            # Generate legacy WIFs (both compressed and uncompressed)
            wif_uncompressed = generate_legacy_wif(private_key_hex)
            wif_compressed = generate_legacy_wif(private_key_hex, compressed=True)
            
            # Generating keyhash for native Bech32 address
            public_key = private_key_to_public_key(private_key_hex)
			
            compressed_public_key = compress_public_key(public_key)
            native_bech32_address = generate_Bech32_address(compressed_public_key)
            
            # Print details
            print("PRIVATE KEY:", private_key_bytes)
            print("PRIVATE NSEC KEY:", converted_nsec_address)
            print("PUBLIC KEY:", compressed_public_key.hex()[1:]) #remove the leadeding 03 used for btc
            print("PUBLIC NPUB KEY:", convert_to_npub(compressed_public_key[1:]))
            print("Legacy BTC RECEIVE ADDRESSES:")
            print("Uncompressed Legacy Address:", legacy_address_uncompressed)
            print("Compressed Legacy Address:", legacy_address_compressed)
            print("")
            print("Public address & wallet")
            print("Native Bech32 SegWit Address:", native_bech32_address)
            print("PRIVATE WALLET IMPORT FORMAT:")
            print("Uncompressed WIF:", wif_uncompressed)
            print("Compressed WIF:", wif_compressed)
            
            wif_compressed_qr = qrcode.make(wif_compressed)
            wif_compressed_qr.save('private_wallet_import_wif_compressed_qr.png')
            
            native_bech32_address_qr = qrcode.make(native_bech32_address)
            native_bech32_address_qr.save('from_private_key_native_bech32_address_qr.png')
        
        elif choice == '3':
            print("Exiting the program.")
            break
        
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
