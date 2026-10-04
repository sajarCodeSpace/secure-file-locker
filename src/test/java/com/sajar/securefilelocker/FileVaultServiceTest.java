package com.sajar.securefilelocker;

import com.sajar.securefilelocker.dto.FileResponse;
import com.sajar.securefilelocker.exception.ApiExceptions;
import com.sajar.securefilelocker.model.StoredFile;
import com.sajar.securefilelocker.repository.StoredFileRepository;
import com.sajar.securefilelocker.service.CryptoService;
import com.sajar.securefilelocker.service.FileVaultService;
import com.sajar.securefilelocker.service.StorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FileVaultServiceTest {

    @Mock
    private StoredFileRepository storedFileRepository;

    @Mock
    private StorageService storageService;

    @Mock
    private CryptoService cryptoService;

    @InjectMocks
    private FileVaultService fileVaultService;

    private StoredFile sampleFile;

    @BeforeEach
    void setUp() {
        sampleFile = StoredFile.builder()
                .id(10L)
                .userId(1L)
                .originalFilename("secret.txt")
                .storedFilename("uuid-blob.enc")
                .sizeBytes(128L)
                .uploadedAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("Upload encrypts and stores file blob, saving metadata")
    void upload_success() {
        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "my_document.pdf", "application/pdf", "dummy pdf content".getBytes(StandardCharsets.UTF_8)
        );

        when(storedFileRepository.save(any(StoredFile.class))).thenReturn(sampleFile);

        FileResponse response = fileVaultService.upload(1L, multipartFile, "password123");

        assertNotNull(response);
        assertEquals(sampleFile.getId(), response.id());
        verify(cryptoService).encrypt(any(InputStream.class), any(OutputStream.class), eq("password123"));
        verify(storageService).store(anyString(), any(InputStream.class));
        verify(storedFileRepository).save(any(StoredFile.class));
    }

    @Test
    @DisplayName("Upload empty file throws FileAccessException")
    void upload_emptyFile_throwsException() {
        MockMultipartFile emptyFile = new MockMultipartFile("file", "empty.txt", "text/plain", new byte[0]);

        assertThrows(ApiExceptions.FileAccessException.class, () ->
                fileVaultService.upload(1L, emptyFile, "password123"));

        verify(storageService, never()).store(anyString(), any());
    }

    @Test
    @DisplayName("List files returns only files owned by the specified userId")
    void listFiles_returnsUserFiles() {
        when(storedFileRepository.findByUserId(1L)).thenReturn(List.of(sampleFile));

        List<FileResponse> files = fileVaultService.listFiles(1L);

        assertEquals(1, files.size());
        assertEquals(sampleFile.getOriginalFilename(), files.get(0).originalFilename());
    }

    @Test
    @DisplayName("Download decrypts file when owned by user")
    void download_success() {
        byte[] decryptedBytes = "decrypted content".getBytes(StandardCharsets.UTF_8);
        when(storedFileRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(sampleFile));
        when(storageService.load("uuid-blob.enc")).thenReturn(new ByteArrayInputStream("encrypted".getBytes()));

        doAnswer(invocation -> {
            OutputStream out = invocation.getArgument(1);
            out.write(decryptedBytes);
            return null;
        }).when(cryptoService).decrypt(any(InputStream.class), any(OutputStream.class), eq("password123"));

        FileVaultService.DecryptedFile result = fileVaultService.download(1L, 10L, "password123");

        assertNotNull(result);
        assertEquals("secret.txt", result.originalFilename());
        assertArrayEquals(decryptedBytes, result.content());
    }

    @Test
    @DisplayName("Download with wrong user ID or nonexistent file throws ResourceNotFoundException (IDOR protection)")
    void download_unauthorizedUser_throwsNotFound() {
        when(storedFileRepository.findByIdAndUserId(10L, 2L)).thenReturn(Optional.empty());

        assertThrows(ApiExceptions.ResourceNotFoundException.class, () ->
                fileVaultService.download(2L, 10L, "password123"));

        verify(cryptoService, never()).decrypt(any(), any(), any());
    }

    @Test
    @DisplayName("Delete removes blob from storage and deletes metadata record")
    void delete_success() {
        when(storedFileRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(sampleFile));

        fileVaultService.delete(1L, 10L);

        verify(storageService).delete("uuid-blob.enc");
        verify(storedFileRepository).delete(sampleFile);
    }
}
