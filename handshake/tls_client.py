import socket
import ssl
from pathlib import Path


CA_CERTIFICATE = Path(
    "certificates/ca/ca_certificate.pem"
)


def start_tls_client(
    caller_certificate: str,
    caller_private_key: str,
    host: str = "127.0.0.1",
    port: int = 8443
):

    # Create TLS client configuration
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    # Trust certificates issued by our CA
    context.load_verify_locations(
        cafile=str(CA_CERTIFICATE)
    )

    # Caller presents its own certificate
    # and proves possession of its private key
    context.load_cert_chain(
        certfile=caller_certificate,
        keyfile=caller_private_key
    )

    # For this prototype we verify our CA chain.
    # Hostname verification is disabled because
    # our user certificates are identities, not
    # website/domain certificates.
    context.check_hostname = False

    context.verify_mode = ssl.CERT_REQUIRED


    try:

        # Create TCP connection
        with socket.create_connection(
            (host, port)
        ) as connection:

            # ----------------------------------
            # TLS HANDSHAKE HAPPENS HERE
            # ----------------------------------

            with context.wrap_socket(
                connection,
                server_hostname=None
            ) as tls_connection:

                print(
                    "Caller: TLS handshake successful!"
                )

                # Get receiver certificate
                receiver_certificate = (
                    tls_connection.getpeercert()
                )

                print(
                    "Receiver certificate:"
                )

                print(
                    receiver_certificate
                )


                # Receive server response
                response = (
                    tls_connection.recv(1024)
                )

                print(
                    response.decode()
                )


    except ssl.SSLError as error:

        print(
            "Caller: TLS handshake FAILED!"
        )

        print(error)


    except ConnectionRefusedError:

        print(
            "Could not connect to receiver."
        )


if __name__ == "__main__":

    start_tls_client(
        caller_certificate="certificates/users/9/certificate.pem",
        caller_private_key="certificates/users/9/private_key.pem"
    )