package com.careflow.authentication_service.dto.response;

public record RegisterResponse(
        Long id,
        String fullName,
        String email,
        String role,
        String message
) {
}
