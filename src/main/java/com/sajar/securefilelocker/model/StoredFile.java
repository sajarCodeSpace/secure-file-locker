package com.sajar.securefilelocker.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "files", indexes = {
        @Index(name = "idx_files_user_id", columnList = "userId")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StoredFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false)
    private String originalFilename;

    // Name of the encrypted blob on disk. Salt + IV are embedded in the
    // ciphertext itself (see CryptoService) - nothing secret is stored here.
    @Column(nullable = false, unique = true)
    private String storedFilename;

    @Column(nullable = false)
    private Long sizeBytes;

    @Column(nullable = false)
    private LocalDateTime uploadedAt;
}
