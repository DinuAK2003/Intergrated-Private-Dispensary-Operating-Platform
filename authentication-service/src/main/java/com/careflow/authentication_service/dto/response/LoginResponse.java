package com.careflow.authentication_service.dto.response;

public record LoginResponse(
        Long id,
        String fullName,
        String email,
        String role,
        String accessToken,
        String tokenType,
        String message
) {
}
