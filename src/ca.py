import json
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class CertificateAuthority:
    """Simula uma Autoridade Certificadora (AC) de uma PKI."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def issue_certificate(
        self, sensor_id: str, sensor_public_key_pem: bytes, validity_days: int = 365
    ) -> dict:
        """Gera um certificado digital simplificado, assinado pela AC."""
        cert = {
            "sensor_id": sensor_id,
            "public_key": sensor_public_key_pem.decode(),
            "validade": (datetime.now() + timedelta(days=validity_days)).strftime(
                "%Y-%m-%d"
            ),
        }

        cert_bytes = json.dumps(cert, sort_keys=True).encode()
        signature = self.private_key.sign(
            cert_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        cert["ca_signature"] = signature.hex()
        return cert

    def verify_certificate(self, cert: dict) -> bool:
        """Verifica a assinatura da AC sobre o certificado."""
        cert_copy = dict(cert)
        signature = bytes.fromhex(cert_copy.pop("ca_signature"))
        cert_bytes = json.dumps(cert_copy, sort_keys=True).encode()

        try:
            self.public_key.verify(
                signature,
                cert_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            return True

        except InvalidSignature:
            return False
