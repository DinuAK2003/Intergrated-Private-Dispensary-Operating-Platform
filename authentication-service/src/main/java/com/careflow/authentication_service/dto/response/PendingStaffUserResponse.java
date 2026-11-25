package com.careflow.authentication_service.dto.response;

import java.time.LocalDateTime;

public record PendingStaffUserResponse(
        Long id,
        String fullName,
        String email,
        String role,
        LocalDateTime createdAt
) {}
