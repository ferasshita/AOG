"""
Entrypoint to run FastAPI server.

By default, this runs without TLS termination; we expect TLS to be handled by a reverse proxy
which forwards signed client certificate headers. For small deployments you can run uvicorn with
an SSLContext for mTLS by setting SERVER_CERT/SERVER_KEY/CA_CERT and letting uvicorn handle mTLS.

Environment:
- SERVER_CERT, SERVER_KEY, CA_CERT (optional) 
- If SERVER_CERT and SERVER_KEY and CA_CERT are provided, uvicorn will run with SSLContext requiring client certs.
"""

import os
import ssl
import uvicorn

if __name__ == "__main__":
    certfile = os.environ.get("SERVER_CERT")
    keyfile = os.environ.get("SERVER_KEY")
    ca_cert = os.environ.get("CA_CERT")

    # If certs are provided, enable mTLS at app server
    if certfile and keyfile and ca_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ssl_context.load_verify_locations(cafile=ca_cert)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        uvicorn.run("app.main:app", host="0.0.0.0", port=8443, ssl_context=ssl_context, log_level="info")
    else:
        # Run plain HTTP (use only for internal dev with a trusted TLS terminator)
        uvicorn.run("app.main:app", host="0.0.0.0", port=8080, log_level="info")