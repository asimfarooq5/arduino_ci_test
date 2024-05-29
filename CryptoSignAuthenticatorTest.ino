#include <Arduino.h>
#include <Ed25519.h>

void generateKeys(uint8_t* privateKey, uint8_t* publicKey) {
    // Generate private and public keys
    Ed25519::generatePrivateKey(privateKey);
    Ed25519::derivePublicKey(publicKey, privateKey);
}

void bytesToHexString(const uint8_t* bytes, int length, char* hex) {
    for (int i = 0; i < length; ++i) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
    hex[2 * length] = '\0';
}

void setup() {
    Serial.begin(115200);

    // Generate a new private key and public key
    uint8_t privateKey[ED25519_PRIVATE_KEY_SIZE];
    uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE];
    generateKeys(privateKey, publicKey);

    // Print the keys
    char privateKeyHex[2 * ED25519_PRIVATE_KEY_SIZE + 1];
    char publicKeyHex[2 * ED25519_PUBLIC_KEY_SIZE + 1];
    bytesToHexString(privateKey, ED25519_PRIVATE_KEY_SIZE, privateKeyHex);
    bytesToHexString(publicKey, ED25519_PUBLIC_KEY_SIZE, publicKeyHex);

    Serial.println("Private Key: " + String(privateKeyHex));
    Serial.println("Public Key: " + String(publicKeyHex));

    // Example usage
    String authid = "user123";
    String authExtra = "{}"; // or some other JSON string

    CryptoSignAuthenticator authenticator(authid, privateKey, authExtra);

    String challengeHex = "a1b2c3d4e5f67890123456789abcdef0"; // Example challenge
    String authenticateMessage = authenticator.authenticate(challengeHex);

    Serial.println("Authenticate Message: " + authenticateMessage);
}

void loop() {
    // Main loop
}

