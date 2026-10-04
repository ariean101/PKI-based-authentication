import socket
import ssl
from pathlib import Path


CA_CERTIFICATE = Path("certificates/ca/ca_certificate.pem")


def start_tls_server(
    receiver_certificate: str,
    receiver_private_key: str,
    host: str = "127.0.0.1",
    port: int = 8443
):

    # Create TLS server configuration
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    # Receiver proves its identity using
    # its certificate + private key
    context.load_cert_chain(
        certfile=receiver_certificate,
        keyfile=receiver_private_key
    )

    # Trust certificates issued by OUR CA
    context.load_verify_locations(
        cafile=str(CA_CERTIFICATE)
    )

    # IMPORTANT:
    # Caller MUST provide a certificate
    context.verify_mode = ssl.CERT_REQUIRED


    # Create normal TCP socket
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server_socket:

        server_socket.bind(
            (host, port)
        )

        server_socket.listen(5)

        print(
            f"Receiver waiting on {host}:{port}"
        )

        connection, address = (
            server_socket.accept()
        )

        print(
            f"TCP connection from {address}"
        )


        # ---------------------------------
        # TLS HANDSHAKE HAPPENS HERE
        # ---------------------------------

        try:

            with context.wrap_socket(
                connection,
                server_side=True
            ) as tls_connection:

                print(
                    "TLS handshake successful!"
                )

                # Get caller certificate
                caller_certificate = (
                    tls_connection.getpeercert()
                )

                print(
                    "Caller certificate:"
                )

                print(
                    caller_certificate
                )

                tls_connection.sendall(
                    b"Authenticated call accepted"
                )


        except ssl.SSLError as error:

            print(
                "TLS handshake FAILED!"
            )

            print(
                error
            )



if __name__ == "__main__":

    start_tls_server(
        receiver_certificate="certificates/users/8/certificate.pem",
        receiver_private_key="certificates/users/8/private_key.pem"
    )