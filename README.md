# Tarefa de desenvolvimento

Esse repositório é destinado a uma tarefa de desenvolvimento na aula de Segurança em IOT.

### 1. Hashing — Integridade dos Dados do Sensor
Sensor de temperatura IoT envia leituras (ex: `{"sensor_id": "Temp01", "temperatura": 20.5, "timestamp": 145600}`) para um Gateway IoT.

- Função que recebe a string de dados e gera hash **SHA-256**, exibindo no console.
- Validação no lado do servidor: simular recebimento da string, fazer **split** dos campos (extrair e exibir cada campo) e verificar o hash.

### 2. Assinatura Digital, Autenticação de Dispositivos (Criptografia Assimétrica)
Evitar que dispositivo falso envie dados em nome do sensor, usando **RSA** ou **ECC** (sugestão: implementar ambos).

- a) Gerar par de chaves (pública/privada) para o dispositivo IoT.
- b) Assinar com a chave privada o hash do Exercício 1. Resultado = mensagem original + assinatura digital.

### 3. Verificação de Assinatura, Lado do Servidor
Função que recebe mensagem, assinatura digital e chave pública do sensor (do Ex. 2).

- Exibir mensagem confirmando se a assinatura é **válida** (origem autêntica e dados íntegros) ou **inválida**.

### 4. Certificado Digital, Simulação de PKI/ICP
Simular Autoridade Certificadora (AC) para evitar Man-in-the-Middle, garantindo confiança nas chaves públicas dos sensores.

- Script que gera "Certificado Digital" simplificado (JSON) contendo: ID do sensor, Chave Pública do sensor, Data de Validade e Assinatura Digital da AC (feita com a chave privada da AC).

## Estrutura do projeto

- `main.py` — ponto de entrada
- `src/sensor.py` — lógica do sensor (geração de dados, hash, assinatura)
- `src/server.py` — lógica do servidor (validação de hash e assinatura)
- `src/utils.py` — funções auxiliares
