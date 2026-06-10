from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from src.utils import generate_sha256_hash


class Sensor:
    """Representa um dispositivo IoT (sensor) com par de chaves RSA."""

    def __init__(self, sensor_id: str):
        self.sensor_id = sensor_id
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_data(self, temperatura: float, timestamp: int) -> str:
        return f"sensor_id:{self.sensor_id},temperatura:{temperatura},timestamp:{timestamp}"

    def generate_hash(self, data: str) -> str:
        return generate_sha256_hash(data)

    def sign_data(self, data_hash: str) -> bytes:
        """Assina o hash dos dados com a chave privada do sensor."""
        return self.private_key.sign(
            data_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
