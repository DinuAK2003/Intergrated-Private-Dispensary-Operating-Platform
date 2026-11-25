package com.careflow.authentication_service.dto.response;

public record CreateStaffUserResponse(
        Long id,
        String fullName,
        String email,
        String role,
        String message
) {
}
