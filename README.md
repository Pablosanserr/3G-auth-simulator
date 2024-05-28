# Mobile Network Authentication and Key Generation Project

This project implements a system for authentication and key generation for mobile networks using AES encryption and HMAC-SHA-256 algorithms. The code is structured into several classes to simulate the components of a mobile network, including the User Identity Module (UIM), the mobile device, the antenna, and the network operator.

## Requirements

- Python 3.x
- PyCryptodome (`pip install pycryptodome`)

## Code Structure

### Classes

#### `UIM`
This class represents the User Identity Module. It includes methods to generate MAC and derive keys using specific algorithms.

- `__init__(self, K)`: Initializes the class with the secret key `K`.
- `f1_algorithm(self, K, SQN, RAND, AMF)`: Generates a 64-bit MAC.
- `f2_algorithm(self, K, RAND)`: Derives the response key (`XRES`) of 32 bits.
- `f3_algorithm(self, K, RAND)`: Derives the cipher key (`CK`) of 128 bits.
- `f4_algorithm(self, K, RAND)`: Derives the integrity key (`IK`) of 128 bits.
- `f5_algorithm(self, K, RAND)`: Derives the anonymity key (`AK`) of 48 bits.
- `set_RAND(self, RAND)`: Sets the `RAND` value.
- `set_MAC(self, AUTHN_MAC)`: Sets the `AUTHN_MAC` value.

#### `Movil`
Represents the mobile device.

- `__init__(self, IMSI)`: Initializes the class with the International Mobile Subscriber Identity (`IMSI`).
- `set_RAND(self, RAND)`: Sets the `RAND` value.
- `set_MAC(self, AUTHN_MAC)`: Sets the `AUTHN_MAC` value.

#### `Antena`
Represents the base station.

- `__init__(self)`: Initializes the class.
- `set_IMSI(self, IMSI)`: Sets the `IMSI` value.
- `set_parameters(self, IMSI, RAND, XRES, AUTHN, CK, IK)`: Sets the authentication and key parameters.

#### `Operador`
Represents the network operator.

- `__init__(self)`: Initializes the class.
- `f1_algorithm(self, K, SQN, RAND, AMF)`: Generates a 64-bit MAC.
- `f2_algorithm(self, K, RAND)`: Derives the response key (`XRES`) of 32 bits.
- `f3_algorithm(self, K, RAND)`: Derives the cipher key (`CK`) of 128 bits.
- `f4_algorithm(self, K, RAND)`: Derives the integrity key (`IK`) of 128 bits.
- `f5_algorithm(self, K, RAND)`: Derives the anonymity key (`AK`) of 48 bits.
- `calcularCON_SQN(self, SQN, AK, K)`: Calculates `CON_SQN`.
- `calcularAUTHN(self, CON_SQN, AMF, MAC, K)`: Calculates `AUTHN`.
- `set_IMSI(self, IMSI)`: Sets the `IMSI` value and generates the necessary parameters.
- `generate_RAND(self)`: Generates a random `RAND` value.
- `generate_SQN(self)`: Generates a random `SQN` value.
- `get_parameters(self)`: Returns the authentication and key parameters.

### Process Flow

1. **Send IMSI from the mobile to the antenna:**
    \`\`\`python
    antena.set_IMSI(movil.IMSI)
    \`\`\`

2. **Send IMSI from the antenna to the operator:**
    \`\`\`python
    operador.set_IMSI(antena.IMSI)
    \`\`\`

3. **Generate and send parameters from the operator to the antenna:**
    \`\`\`python
    operador.set_IMSI(IMSI)
    IMSI, RAND, XRES, AUTHN, CK, IK = operador.get_parameters()
    antena.set_parameters(IMSI, RAND, XRES, AUTHN, CK, IK)
    \`\`\`

4. **Send RAND and AUTHN->MAC from the antenna to the mobile:**
    \`\`\`python
    movil.set_RAND(antena.RAND)
    # movil.set_MAC(antena.AUTHN_MAC)
    \`\`\`

5. **Send RAND and AUTHN->MAC from the mobile to the UIM:**
    \`\`\`python
    uim.set_RAND(movil.RAND)
    # uim.set_MAC(movil.AUTHN_MAC)
    \`\`\`

6. **Generate all parameters in UIM and send them to the mobile.**

7. **Send RES from the mobile to the antenna.**

8. **The antenna checks if RES == XRES and responds with OK (to the mobile).**

9. **Send the encoded "Hello" message from the mobile to the antenna.**

10. **Send HMAC from the mobile to the antenna.**

## Usage

To run the code, simply execute the main script. Make sure you have all the required dependencies installed.

\`\`\`bash
python main.py
\`\`\`

## Contributions

Contributions are welcome. Please open an issue to discuss any major changes before submitting a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---
