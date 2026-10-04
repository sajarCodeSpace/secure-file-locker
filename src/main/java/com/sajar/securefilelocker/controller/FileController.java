package com.sajar.securefilelocker.controller;

import com.sajar.securefilelocker.dto.FileResponse;
import com.sajar.securefilelocker.security.AuthenticatedUser;
import com.sajar.securefilelocker.service.FileVaultService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/files")
@Tag(name = "File Vault", description = "Endpoints for encrypted file upload, listing, zero-knowledge download, and deletion")
@SecurityRequirement(name = "Bearer Authentication")
public class FileController {

    private final FileVaultService fileVaultService;

    public FileController(FileVaultService fileVaultService) {
        this.fileVaultService = fileVaultService;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload and encrypt a file", description = "Encrypts the file payload using AES-256-GCM with a key derived from the supplied password via PBKDF2 (120,000 iterations).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "File encrypted and stored successfully"),
            @ApiResponse(responseCode = "400", description = "Empty file or missing password"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Missing or invalid JWT"),
            @ApiResponse(responseCode = "413", description = "File exceeds max payload limit (25MB)")
    })
    public ResponseEntity<FileResponse> upload(@AuthenticationPrincipal AuthenticatedUser user,
                                               @Parameter(description = "Binary file payload") @RequestParam("file") MultipartFile file,
                                               @Parameter(description = "Password used to derive encryption key") @RequestParam("password") @NotBlank String password) {
        return ResponseEntity.ok(fileVaultService.upload(user.id(), file, password));
    }

    @GetMapping
    @Operation(summary = "List files", description = "Returns metadata for all files owned by the authenticated user.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "List of user files retrieved"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Missing or invalid JWT")
    })
    public ResponseEntity<List<FileResponse>> list(@AuthenticationPrincipal AuthenticatedUser user) {
        return ResponseEntity.ok(fileVaultService.listFiles(user.id()));
    }

    @PostMapping("/{id}/download")
    @Operation(summary = "Download and decrypt a file", description = "Supplies the file password in the request body to decrypt and stream the original file bytes. Password is authenticated by GCM tag verification.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "File decrypted successfully and streamed as attachment", content = @Content(mediaType = MediaType.APPLICATION_OCTET_STREAM_VALUE)),
            @ApiResponse(responseCode = "400", description = "Password cannot be blank"),
            @ApiResponse(responseCode = "401", description = "Incorrect password or tampered ciphertext"),
            @ApiResponse(responseCode = "404", description = "File not found or not owned by user"),
            @ApiResponse(responseCode = "429", description = "Decryption attempt rate limit exceeded")
    })
    public ResponseEntity<ByteArrayResource> download(@AuthenticationPrincipal AuthenticatedUser user,
                                                      @PathVariable Long id,
                                                      @Valid @RequestBody DownloadRequest request) {
        var decrypted = fileVaultService.download(user.id(), id, request.password());

        ContentDisposition disposition = ContentDisposition.attachment()
                .filename(decrypted.originalFilename(), StandardCharsets.UTF_8)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(new ByteArrayResource(decrypted.content()));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an encrypted file", description = "Deletes the encrypted blob from storage and removes metadata from the database.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "File deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Missing or invalid JWT"),
            @ApiResponse(responseCode = "404", description = "File not found or not owned by user")
    })
    public ResponseEntity<Void> delete(@AuthenticationPrincipal AuthenticatedUser user, @PathVariable Long id) {
        fileVaultService.delete(user.id(), id);
        return ResponseEntity.noContent().build();
    }

    public record DownloadRequest(
            @NotBlank(message = "Password cannot be blank")
            @Schema(description = "The decryption password", example = "my-secret-vault-pass")
            String password
    ) {}
}
