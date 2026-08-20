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
 * LENGTH HIDING (padding)
 * -----------------------
 * A sealed box does not pad, so ciphertext length = plaintext length + 48.
 * For short, low-entropy fields (yes/no, a checkbox "1", etc.) that length
 * alone can betray the value. To stop that, we frame every plaintext as:
 *
 *     [ 4-byte big-endian length ][ plaintext ][ zero padding ]
 *
 * and pad the whole thing up to the next multiple of PAD_BLOCK. Because the
 * true length is stored explicitly in the prefix, decryption takes exactly
 * that many bytes — the padding is never guessed at, so ANY plaintext
 * (including one containing or ending in the padding byte) round-trips
 * perfectly. Every value up to PAD_BLOCK - 4 bytes produces an identical
 * ciphertext length, so short fields become indistinguishable by size.
 *
 * NOTE: this framing is a fixed format. If you have already stored data
 * encrypted with a different padding scheme, it will NOT decrypt with this
 * version — migrate before switching, or version your stored records.
 *
 *
 * THE THREE OPERATIONS
 * --------------------
 *   1. generate_keypair() → run ONCE, OFF the server. Produces A and B.
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
 * Requires: PHP 8.3+ with libsodium (bundled in core since PHP 7.2 — no
 * extension to install).
 */
final class SealedBox
{
    /** Base64 variant used for every key and ciphertext this class emits. */
    private const B64_VARIANT = SODIUM_BASE64_VARIANT_ORIGINAL;

    /**
     * Plaintext is padded up to the next multiple of this many bytes.
     * All values up to (PAD_BLOCK - 4) bytes share one ciphertext length,
     * so they cannot be told apart by size. 256 comfortably covers emails,
     * phone numbers, names and yes/no fields in a single block.
     */
    private const PAD_BLOCK = 256;

    /** Bytes used for the length prefix (big-endian uint32 => up to 4 GB). */
    private const LENGTH_PREFIX_BYTES = 4;

    // -------------------------------------------------------------------
    // 1. KEY GENERATION  (run ONCE, OFF the server)
    // -------------------------------------------------------------------

    /**
     * Generate a fresh keypair.
     *
     * @return array{public: string, secret: string} Both base64-encoded.
     */
    public static function generate_keypair(): array
    {
        $keypair = sodium_crypto_box_keypair();

        $public = sodium_crypto_box_publickey($keypair);
        $secret = sodium_crypto_box_secretkey($keypair);

        $result = [
            'public' => sodium_bin2base64($public, self::B64_VARIANT),
            'secret' => sodium_bin2base64($secret, self::B64_VARIANT),
        ];

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
     * secret key can read it. The plaintext is length-hidden by padding.
     *
     * @param string $plaintext    The data to protect.
     * @param string $publicKeyB64 Key A, base64 (from generate_keypair()).
     * @return string              Base64 ciphertext, safe to store in a DB.
     *
     * @throws InvalidArgumentException If the public key is malformed.
     */
    public static function encrypt(string $plaintext, string $publicKeyB64): string
    {
        $publicKey = self::decode_key(
            $publicKeyB64,
            SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
            'public'
        );

        $padded     = self::pad($plaintext);
        $ciphertext = sodium_crypto_box_seal($padded, $publicKey);

        sodium_memzero($padded);

        return sodium_bin2base64($ciphertext, self::B64_VARIANT);
    }

    // -------------------------------------------------------------------
    // 3. DECRYPT  (runs OFF the server — needs Key B)
    // -------------------------------------------------------------------

    /**
     * Decrypt ciphertext produced by encrypt().
     *
     * @param string $ciphertextB64 Base64 ciphertext from encrypt().
     * @param string $secretKeyB64  Key B, base64 (from generate_keypair()).
     * @return string               The recovered plaintext.
     *
     * @throws InvalidArgumentException If a key or the ciphertext is malformed.
     * @throws RuntimeException         If decryption fails (wrong key or tampering).
     */
    public static function decrypt(string $ciphertextB64, string $secretKeyB64): string
    {
        $secretKey = self::decode_key(
            $secretKeyB64,
            SODIUM_CRYPTO_BOX_SECRETKEYBYTES,
            'secret'
        );

        $ciphertext = sodium_base642bin($ciphertextB64, self::B64_VARIANT);

        $publicKey = sodium_crypto_box_publickey_from_secretkey($secretKey);
        $keypair   = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secretKey,
            $publicKey
        );

        $padded = sodium_crypto_box_seal_open($ciphertext, $keypair);

        sodium_memzero($secretKey);
        sodium_memzero($keypair);

        if ($padded === false) {
            throw new RuntimeException(
                'Decryption failed: wrong secret key or the data was tampered with.'
            );
        }

        $plaintext = self::unpad($padded);
        sodium_memzero($padded);

        return $plaintext;
    }

    // -------------------------------------------------------------------
    // Padding helpers (length hiding)
    // -------------------------------------------------------------------

    /**
     * Frame with a 4-byte length prefix, then zero-pad up to the next
     * multiple of PAD_BLOCK. The prefix makes unpadding exact and lossless
     * for arbitrary binary plaintext.
     */
    private static function pad(string $plaintext): string
    {
        $framed = pack('N', strlen($plaintext)) . $plaintext;

        $blocks    = (int) ceil(strlen($framed) / self::PAD_BLOCK);
        $targetLen = max(1, $blocks) * self::PAD_BLOCK;

        // The padding bytes are encrypted, so their content never leaks;
        // zero bytes are fine and cheap.
        return str_pad($framed, $targetLen, "\0", STR_PAD_RIGHT);
    }

    /**
     * Reverse pad(): read the length prefix and return exactly that many
     * bytes of plaintext.
     */
    private static function unpad(string $padded): string
    {
        if (strlen($padded) < self::LENGTH_PREFIX_BYTES) {
            throw new RuntimeException('Malformed padded plaintext (too short for length prefix).');
        }

        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', substr($padded, 0, self::LENGTH_PREFIX_BYTES));
        $length   = $unpacked[1];

        $available = strlen($padded) - self::LENGTH_PREFIX_BYTES;
        if ($length < 0 || $length > $available) {
            throw new RuntimeException('Corrupt length prefix in decrypted data.');
        }

        return substr($padded, self::LENGTH_PREFIX_BYTES, $length);
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /**
     * Decode and validate a base64 key to raw bytes of the expected length.
     */
    private static function decode_key(string $keyB64, int $expectedBytes, string $label): string
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
