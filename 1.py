import socket
import ssl
import binascii

def create_ssl_context(certfile):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(certfile)
    return context

def send_hex_data_and_receive_response(server_address, server_port, certfile, hex_data):
    # Create an SSL context
    context = create_ssl_context(certfile)

    # Connect to the server
    with socket.create_connection((server_address, server_port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_address) as ssock:
            print("SSL established. Peer: {}".format(ssock.getpeercert()))

            # Convert hex data to binary data
            binary_data = binascii.unhexlify(hex_data)
            
            # Send the binary data
            ssock.sendall(binary_data)
            print(f"Sent: {hex_data}")

            # Receive the response from the server
            response = ssock.recv(4096)
            print("Received:", response)

            # If you expect the response in hex, convert it back to hex
            hex_response = binascii.hexlify(response).decode('utf-8')
            print("Hex Response:", hex_response)

if __name__ == "__main__":
    SERVER_ADDRESS = 'your_server_address'  # Replace with your server address
    SERVER_PORT = 12345  # Replace with your server port
    CERTFILE = 'path_to_self_signed_cert.pem'  # Replace with your self-signed certificate file path
    HEX_DATA = '48656c6c6f2c20576f726c6421'  # Example hex data (Hello, World!)

    send_hex_data_and_receive_response(SERVER_ADDRESS, SERVER_PORT, CERTFILE, HEX_DATA)
