package com.sajar.securefilelocker.repository;

import com.sajar.securefilelocker.model.StoredFile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface StoredFileRepository extends JpaRepository<StoredFile, Long> {
    List<StoredFile> findByUserId(Long userId);
    Optional<StoredFile> findByIdAndUserId(Long id, Long userId);
}
