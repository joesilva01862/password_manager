import base64
import sys

def decode_key(encoded_key):
    print(f'base64 encoded string: {encoded_key}')

    # this gives us bytes
    decoded_str = base64.b64decode(encoded_key)

    # convert bytes to string
    decoded_str = decoded_str.decode('utf-8')
    print(f'Plain text: {decoded_str}')

def encode_key(key):
    # create a bytes object
    encoded = base64.b64encode(bytes(key, 'utf-8'))
    
    # creates a string object
    encoded_str = encoded.decode('utf-8')

    print(f' Goes into the encrypt.dat enckey: {encoded_str}')
    iv = 'CADACAFEBEEFDEDA'
    encoded = base64.b64encode(bytes(iv, 'utf-8'))
    encoded_str = encoded.decode('utf-8')

    print(f'     Goes into the encrypt.dat iv: {encoded_str}')
    print(f'Goes into the browser\'s init page: {key}')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: program -encode|-decode key.")
        exit()

    if sys.argv[1] == '-enc':
        encode_key(sys.argv[2])

    if sys.argv[1] == '-dec':
        decode_key(sys.argv[2])    