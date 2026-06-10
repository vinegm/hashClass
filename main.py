import json

from src.sensor import Sensor
from src.server import GatewayServer
from src.ca import CertificateAuthority
from src.utils import load_public_key_from_pem


def exercicio1() -> None:
    sensor = Sensor("Exercicio1")
    server = GatewayServer()

    print("\nExercicio 1: Hash dos dados do sensor")

    data = sensor.generate_data(20.5, 145600)
    print("Dados:", data)

    data_hash = sensor.generate_hash(data)
    print("Hash SHA-256:", data_hash)

    print("\nExercicio 1 (validacao): servidor recebe e valida o hash")
    parsed_data = server.parse_data(data)
    print("Dados parseados no servidor:")
    print(json.dumps(parsed_data, indent=2))

    valid_hash = server.receive_data(data, data_hash)
    print("Hash valido?", valid_hash)


def exercicio2() -> None:
    sensor = Sensor("Exercicio2")

    data = sensor.generate_data(20.5, 145600)
    data_hash = sensor.generate_hash(data)
    signature = sensor.sign_data(data_hash)

    print("\nExercicio 2: chaves RSA e assinatura digital")

    print("Chave publica do sensor:")
    print(sensor.get_public_key_pem().decode())

    print("Assinatura (hex):", signature.hex())


def exercicio3() -> None:
    def validate_signature(
        sensor: Sensor, server: GatewayServer, data_hash: str, signature: bytes
    ) -> None:
        """Auxiliar para validar a assinatura no servidor usando a chave publica do sensor e mostrar o resultado."""
        valid = server.verify_signature(sensor.public_key, data_hash, signature)

        if valid:
            print("Assinatura valida: dados autênticos e íntegros")
            return

        print("Assinatura invalida: dados adulterados ou assinatura forjada")

    sensor = Sensor("Exercicio3")
    server = GatewayServer()

    data = sensor.generate_data(20.5, 145600)
    data_hash = sensor.generate_hash(data)

    false_data = sensor.generate_data(99.9, 145600)
    false_hash = sensor.generate_hash(false_data)

    print("\nExercicio 3: verificacao da assinatura no servidor")
    signature = sensor.sign_data(data_hash)
    validate_signature(sensor, server, data_hash, signature)

    print("\nExercicio 3 (caso invalido): dados adulterados")
    validate_signature(sensor, server, false_hash, signature)


def exercicio4() -> None:
    def validate_certificate(ca: CertificateAuthority, cert: dict) -> None:
        """Auxiliar para validar o certificado usando a AC e mostrar o resultado."""
        cert_valido = ca.verify_certificate(cert)

        if cert_valido:
            print("Certificado VALIDO")
            return

        print("Certificado INVALIDO")

    def processar_mensagem(
        ca: CertificateAuthority, server: GatewayServer, mensagem: dict
    ) -> None:
        """Auxiliar que simula o gateway recebendo e validando uma mensagem do sensor."""
        print(json.dumps(mensagem, indent=2))

        print("\nValidacoes no gateway:")
        if not ca.verify_certificate(mensagem["cert"]):
            print("Certificado INVALIDO, mensagem rejeitada")
            return

        print("Certificado VALIDO")

        sensor_public_key = load_public_key_from_pem(mensagem["cert"]["public_key"])
        assinatura_valida = server.verify_signature(
            sensor_public_key, mensagem["hash"], bytes.fromhex(mensagem["signature"])
        )

        if not assinatura_valida:
            print("Assinatura INVALIDA, mensagem rejeitada")
            return

        print("Assinatura VALIDA")

        hash_valido = server.receive_data(mensagem["data"], mensagem["hash"])
        if not hash_valido:
            print("Hash INVALIDO, dados rejeitados")
            return

        print("Hash VALIDO\ndados aceitos")

    bad_sensor = Sensor("bad_actor")
    sensor = Sensor("Exercicio4")
    server = GatewayServer()
    ca = CertificateAuthority()

    print("\nExercicio 4: certificado digital emitido pela AC")
    cert = ca.issue_certificate(sensor.sensor_id, sensor.get_public_key_pem())
    print(json.dumps(cert, indent=2))

    print("\nExercicio 4 (validacao): verificacao do certificado")
    validate_certificate(ca, cert)

    print("\nExercicio 4 (caso invalido): certificado adulterado")
    bad_cert = ca.issue_certificate(
        bad_sensor.sensor_id, bad_sensor.get_public_key_pem()
    )
    bad_cert["public_key"] = cert["public_key"]
    validate_certificate(ca, bad_cert)

    print(
        "\nExercicio 4 (fluxo completo): sensor envia dados + assinatura + certificado"
    )
    data = sensor.generate_data(20.5, 145600)
    data_hash = sensor.generate_hash(data)
    signature = sensor.sign_data(data_hash)

    mensagem = {
        "data": data,
        "hash": data_hash,
        "signature": signature.hex(),
        "cert": cert,
    }

    processar_mensagem(ca, server, mensagem)

    print(
        "\nExercicio 4 (ataque MITM): atacante intercepta e tenta se passar pelo sensor"
    )

    ca_falsa = CertificateAuthority()
    cert_mitm = ca_falsa.issue_certificate(
        bad_sensor.sensor_id, bad_sensor.get_public_key_pem()
    )

    bad_data = bad_sensor.generate_data(99.9, 145600)
    bad_hash = bad_sensor.generate_hash(bad_data)
    bad_signature = bad_sensor.sign_data(bad_hash)

    mensagem_mitm = {
        "data": bad_data,
        "hash": bad_hash,
        "signature": bad_signature.hex(),
        "cert": cert_mitm,
    }

    processar_mensagem(ca, server, mensagem_mitm)

    print(
        "\nExercicio 4 (ataque MITM): atacante intercepta e tenta alterar os dados sem alterar o certificado"
    )

    mensagem_mitm2 = {
        "data": bad_data,
        "hash": bad_hash,
        "signature": bad_signature.hex(),
        "cert": cert,
    }

    processar_mensagem(ca, server, mensagem_mitm2)


def main():
    opcoes = {
        "1": {"questao": "Hash dos dados do sensor", "funcao": exercicio1},
        "2": {"questao": "Chaves RSA e assinatura digital", "funcao": exercicio2},
        "3": {"questao": "Verificacao da assinatura", "funcao": exercicio3},
        "4": {"questao": "Certificado digital (AC)", "funcao": exercicio4},
    }

    while True:
        print("Selecione o que fazer:")
        for key, value in opcoes.items():
            print(f"{key}. {value['questao']}")
        print("0. Sair")

        escolha = input("> ").strip()
        if escolha == "0":
            break

        opcao = opcoes.get(escolha)
        if opcao is None:
            print("Opcao invalida, tente novamente.")
        else:
            opcao["funcao"]()

        print("\n" + "-" * 40 + "\n")


if __name__ == "__main__":
    main()
