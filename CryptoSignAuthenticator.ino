#include <Arduino.h>
#include <Ed25519.h>
#include <Base64.h>

class CryptoSignAuthenticator {
public:
    CryptoSignAuthenticator(const String& authid, const uint8_t* privateKey, const String& authExtra = "{}")
        : _authid(authid), _authExtra(authExtra) {
        // Store the private key
        _privateKey = new uint8_t[ED25519_PRIVATE_KEY_SIZE];
        memcpy(_privateKey, privateKey, ED25519_PRIVATE_KEY_SIZE);

        // Generate the public key
        _publicKey = new uint8_t[ED25519_PUBLIC_KEY_SIZE];
        Ed25519::derivePublicKey(_publicKey, _privateKey);

        // Add the public key to auth_extra if not present
        if (!authExtra.contains("pubkey")) {
            char pubKeyBase64[BASE64_ENC_LEN(ED25519_PUBLIC_KEY_SIZE)];
            Base64.encode(pubKeyBase64, (char*)_publicKey, ED25519_PUBLIC_KEY_SIZE);
            _authExtra += "\"pubkey\":\"" + String(pubKeyBase64) + "\"";
        }
    }

    ~CryptoSignAuthenticator() {
        delete[] _privateKey;
        delete[] _publicKey;
    }

    String authenticate(const String& challengeHex) {
        // Convert the challenge from hex to bytes
        int challengeLength = challengeHex.length() / 2;
        uint8_t* challenge = new uint8_t[challengeLength];
        hexStringToBytes(challengeHex, challenge, challengeLength);

        // Sign the challenge
        uint8_t signature[ED25519_SIGNATURE_SIZE];
        Ed25519::sign(signature, _privateKey, challenge, challengeLength);

        // Convert signature and challenge back to hex
        char signatureHex[2 * ED25519_SIGNATURE_SIZE + 1];
        bytesToHexString(signature, ED25519_SIGNATURE_SIZE, signatureHex);

        // Combine signature and challenge
        String combinedHex = String(signatureHex) + challengeHex;

        // Clean up
        delete[] challenge;

        return combinedHex;
    }

private:
    String _authid;
    String _authExtra;
    uint8_t* _privateKey;
    uint8_t* _publicKey;

    void hexStringToBytes(const String& hex, uint8_t* bytes, int length) {
        for (int i = 0; i < length; ++i) {
            sscanf(hex.substring(2 * i, 2 * i + 2).c_str(), "%2hhx", &bytes[i]);
        }
    }

    void bytesToHexString(const uint8_t* bytes, int length, char* hex) {
        for (int i = 0; i < length; ++i) {
            sprintf(hex + 2 * i, "%02x", bytes[i]);
        }
        hex[2 * length] = '\0';
    }
};

