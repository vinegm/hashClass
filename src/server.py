from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from src.utils import generate_sha256_hash


class GatewayServer:
    """Simula o Gateway IoT que recebe e valida os dados dos sensores."""

    def parse_data(self, data: str) -> dict:
        """Faz o split da string de dados e retorna um dicionário."""
        campos = {}
        for campo in data.split(","):
            chave, valor = campo.split(":")
            campos[chave] = valor

        return campos

    def receive_data(self, data: str, received_hash: str) -> bool:
        """Recebe a string de dados, faz o split dos campos e valida o hash."""
        return generate_sha256_hash(data) == received_hash

    def verify_signature(self, public_key, message: str, signature: bytes) -> bool:
        """Verifica a assinatura digital usando a chave publica do sensor."""
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            return True

        except InvalidSignature:
            return False
