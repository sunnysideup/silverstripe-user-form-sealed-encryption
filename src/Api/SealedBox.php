<?php

declare(strict_types=1);

namespace Sunnysideup\UserFormSealedEncryption\Api;

use InvalidArgumentException;
use RuntimeException;

/**
 * SealedBox — one-way (asymmetric) encryption using libsodium sealed boxes.
 * =========================================================================
 *
 * WHAT THIS GIVES YOU
 * -------------------
 * Data is encrypted on the server using ONLY the public key (Key A).
 * It can be decrypted ONLY with the secret key (Key B), which never lives
 * on the server. If the server is fully compromised, the attacker can
 * encrypt new data but CANNOT read anything — past or present.
 *
 * This works because libsodium's "sealed box" generates a throwaway
 * ephemeral keypair for every message. The server never holds a long-lived
 * secret of any kind. The public key is all it needs to encrypt.
 *
 *
 * THE THREE OPERATIONS
 * --------------------
 *   1. generateKeypair()  → run ONCE, OFF the server. Produces A and B.
 *   2. encrypt()          → runs ON the server. Needs only Key A (public).
 *   3. decrypt()          → runs OFF the server. Needs Key B (secret).
 *
 *
 * KEY HANDLING RULES (read these)
 * -------------------------------
 *   - Key A (public): put on the server (env var / config). Not sensitive.
 *   - Key B (secret): keep OFF the server, somewhere the server can never
 *     reach — an admin laptop, a hardware token, an offline vault.
 *   - Never commit Key B to git. Never send it through the app.
 *   - Key A can always be re-derived from Key B, so B is the only thing
 *     you must truly protect. Losing B means the data is unrecoverable
 *     (that is the point — there is no backdoor).
 *
 *
 * DATA FORMAT
 * -----------
 * All keys and ciphertext are exchanged as base64 strings using the
 * ORIGINAL variant. Keep the variant consistent — it is baked into the
 * constants below so you don't have to think about it.
 *
 * Requires: PHP 8.3+ with libsodium (bundled in core since PHP 7.2 — no
 * extension to install).
 */
final class SealedBox
{
    /** Base64 variant used for every key and ciphertext this class emits. */
    private const B64_VARIANT = SODIUM_BASE64_VARIANT_ORIGINAL;

    // -------------------------------------------------------------------
    // 1. KEY GENERATION  (run ONCE, OFF the server)
    // -------------------------------------------------------------------

    /**
     * Generate a fresh keypair.
     *
     * Run this once on a trusted, offline-ish machine (your laptop). Put the
     * returned 'public' value on the server; store 'secret' somewhere the
     * server can never see it.
     *
     * @return array{public: string, secret: string} Both base64-encoded.
     */
    public static function generateKeypair(): array
    {
        $keypair = sodium_crypto_box_keypair();

        $public = sodium_crypto_box_publickey($keypair);
        $secret = sodium_crypto_box_secretkey($keypair);

        $result = [
            'public' => sodium_bin2base64($public, self::B64_VARIANT),
            'secret' => sodium_bin2base64($secret, self::B64_VARIANT),
        ];

        // Wipe the raw key material from memory as soon as we're done.
        sodium_memzero($keypair);
        sodium_memzero($public);
        sodium_memzero($secret);

        return $result;
    }

    // -------------------------------------------------------------------
    // 2. ENCRYPT  (runs ON the server — needs only Key A)
    // -------------------------------------------------------------------

    /**
     * Encrypt a plaintext string so that ONLY the holder of the matching
     * secret key can read it.
     *
     * @param string $plaintext    The data to protect.
     * @param string $publicKeyB64 Key A, base64 (as produced by generateKeypair()).
     * @return string              Base64 ciphertext, safe to store in a DB.
     *
     * @throws InvalidArgumentException If the public key is malformed.
     */
    public static function encrypt(string $plaintext, string $publicKeyB64): string
    {
        $publicKey = self::decodeKey(
            $publicKeyB64,
            SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
            'public'
        );

        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);

        return sodium_bin2base64($ciphertext, self::B64_VARIANT);
    }

    // -------------------------------------------------------------------
    // 3. DECRYPT  (runs OFF the server — needs Key B)
    // -------------------------------------------------------------------

    /**
     * Decrypt ciphertext produced by encrypt().
     *
     * Run this OFF the server, on the machine that holds the secret key.
     * The public key is derived from the secret key automatically, so you
     * only ever need to supply Key B.
     *
     * @param string $ciphertextB64 Base64 ciphertext from encrypt().
     * @param string $secretKeyB64  Key B, base64 (from generateKeypair()).
     * @return string               The recovered plaintext.
     *
     * @throws InvalidArgumentException If a key or the ciphertext is malformed.
     * @throws RuntimeException         If decryption fails (wrong key or tampering).
     */
    public static function decrypt(string $ciphertextB64, string $secretKeyB64): string
    {
        $secretKey = self::decodeKey(
            $secretKeyB64,
            SODIUM_CRYPTO_BOX_SECRETKEYBYTES,
            'secret'
        );

        $ciphertext = sodium_base642bin($ciphertextB64, self::B64_VARIANT);

        // Sealed boxes need the FULL keypair to open. We rebuild the public
        // half from the secret key, then assemble the keypair.
        $publicKey = sodium_crypto_box_publickey_from_secretkey($secretKey);
        $keypair   = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secretKey,
            $publicKey
        );

        $plaintext = sodium_crypto_box_seal_open($ciphertext, $keypair);

        // Clean up secret material regardless of outcome.
        sodium_memzero($secretKey);
        sodium_memzero($keypair);

        if ($plaintext === false) {
            throw new RuntimeException(
                'Decryption failed: wrong secret key or the data was tampered with.'
            );
        }

        return $plaintext;
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /**
     * Decode and validate a base64 key to raw bytes of the expected length.
     */
    private static function decodeKey(string $keyB64, int $expectedBytes, string $label): string
    {
        try {
            $raw = sodium_base642bin($keyB64, self::B64_VARIANT);
        } catch (\SodiumException $e) {
            throw new InvalidArgumentException("The {$label} key is not valid base64.", 0, $e);
        }

        if (strlen($raw) !== $expectedBytes) {
            throw new InvalidArgumentException(
                "The {$label} key has the wrong length "
                . '(expected ' . $expectedBytes . ' bytes, got ' . strlen($raw) . ').'
            );
        }

        return $raw;
    }
}
