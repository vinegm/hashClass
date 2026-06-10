import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def generate_sha256_hash(data: str) -> str:
    """Gera o hash SHA-256 (hex) de uma string."""
    return hashlib.sha256(data.encode()).hexdigest()


def load_public_key_from_pem(pem: str) -> RSAPublicKey:
    """Carrega uma chave publica RSA a partir de uma string PEM."""
    return serialization.load_pem_public_key(pem.encode())
