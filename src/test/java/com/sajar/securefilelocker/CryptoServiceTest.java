package com.sajar.securefilelocker;

import com.sajar.securefilelocker.exception.ApiExceptions;
import com.sajar.securefilelocker.service.CryptoService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    private final CryptoService cryptoService = new CryptoService();

    @Test
    @DisplayName("Encrypt and decrypt round-trip with correct password returns original plaintext")
    void encryptThenDecryptWithCorrectPassword_returnsOriginalBytes() {
        byte[] original = "top secret portfolio notes".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();

        cryptoService.encrypt(new ByteArrayInputStream(original), encrypted, "correct-horse-battery-staple");

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        cryptoService.decrypt(new ByteArrayInputStream(encrypted.toByteArray()), decrypted, "correct-horse-battery-staple");

        assertArrayEquals(original, decrypted.toByteArray());
    }

    @Test
    @DisplayName("Decrypt with wrong password throws WrongFilePasswordException due to GCM auth tag mismatch")
    void decryptWithWrongPassword_throwsWrongFilePasswordException() {
        byte[] original = "top secret portfolio notes".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        cryptoService.encrypt(new ByteArrayInputStream(original), encrypted, "correct-password");

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        assertThrows(ApiExceptions.WrongFilePasswordException.class, () ->
                cryptoService.decrypt(new ByteArrayInputStream(encrypted.toByteArray()), decrypted, "wrong-password"));
    }

    @Test
    @DisplayName("Two encryptions of identical plaintext produce distinct ciphertexts due to fresh salt and IV")
    void twoEncryptionsOfSameContent_produceDifferentCiphertext() {
        byte[] original = "identical plaintext".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream encrypted1 = new ByteArrayOutputStream();
        cryptoService.encrypt(new ByteArrayInputStream(original), encrypted1, "same-password");

        ByteArrayOutputStream encrypted2 = new ByteArrayOutputStream();
        cryptoService.encrypt(new ByteArrayInputStream(original), encrypted2, "same-password");

        // Random 16-byte salt + 12-byte IV per call guarantees semantic security (IND-CPA)
        assertFalse(Arrays.equals(encrypted1.toByteArray(), encrypted2.toByteArray()));
    }

    @Test
    @DisplayName("Tampered ciphertext throws WrongFilePasswordException (integrity verification)")
    void tamperedCiphertext_failsAuthentication() {
        byte[] original = "unmodified secret content".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        cryptoService.encrypt(new ByteArrayInputStream(original), encrypted, "secure-pass");

        byte[] cipherBytes = encrypted.toByteArray();
        // Flip bits in the ciphertext portion (after 16 bytes salt + 12 bytes IV = byte 28)
        cipherBytes[28] = (byte) (cipherBytes[28] ^ 0xFF);

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        assertThrows(ApiExceptions.WrongFilePasswordException.class, () ->
                cryptoService.decrypt(new ByteArrayInputStream(cipherBytes), decrypted, "secure-pass"));
    }

    @Test
    @DisplayName("Truncated file without complete salt/IV header throws FileAccessException")
    void truncatedFile_throwsFileAccessException() {
        byte[] tooShort = new byte[10]; // Less than 16 bytes salt + 12 bytes IV
        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();

        assertThrows(ApiExceptions.FileAccessException.class, () ->
                cryptoService.decrypt(new ByteArrayInputStream(tooShort), decrypted, "any-password"));
    }
}
