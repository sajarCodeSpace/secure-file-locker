package com.sajar.securefilelocker.dto;

import java.time.LocalDateTime;

public record FileResponse(
        Long id,
        String originalFilename,
        Long sizeBytes,
        LocalDateTime uploadedAt
) {}
