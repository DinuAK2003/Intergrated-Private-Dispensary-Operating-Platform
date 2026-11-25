package com.careflow.authentication_service.controller;

import com.careflow.authentication_service.dto.request.CreateStaffUserRequest;
import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.response.CreateStaffUserResponse;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.dto.response.PendingStaffUserResponse;
import com.careflow.authentication_service.service.AuthService;
import com.careflow.authentication_service.service.SessionService;
import com.careflow.authentication_service.service.StaffUserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final SessionService sessionService;
    private final StaffUserService staffUserService;

    public AuthController(
            AuthService authService,
            SessionService sessionService,
            StaffUserService staffUserService) {

        this.authService = authService;
        this.sessionService = sessionService;
        this.staffUserService = staffUserService;
    }

    // Staff Login
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request) {

        LoginResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    // Staff Self-Registration
    @PostMapping("/users")
    public ResponseEntity<CreateStaffUserResponse> createStaffUser(
            @Valid @RequestBody CreateStaffUserRequest request) {

        CreateStaffUserResponse response =
                staffUserService.createStaffUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    // Approve Pending Staff Account - ADMIN Only
    @PatchMapping("/users/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> approveStaffUser(
            @PathVariable Long id) {

        staffUserService.approveStaffUser(id);

        return ResponseEntity.ok(Map.of(
                "message", "Staff account approved successfully"
        ));
    }

    // Deactivate Staff Account - ADMIN Only
    @PatchMapping("/users/{id}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deactivateStaffUser(
            @PathVariable Long id) {

        staffUserService.deactivateStaffUser(id);

        return ResponseEntity.ok(Map.of(
                "message", "Staff account deactivated successfully"
        ));
    }

    // Get Current Authenticated User
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            Authentication authentication) {

        List<String> authorities = authentication.getAuthorities()
                .stream()
                .map(authority -> authority.getAuthority())
                .toList();

        Map<String, Object> response = Map.of(
                "email", authentication.getName(),
                "authorities", authorities,
                "message", "Authentication successful"
        );

        return ResponseEntity.ok(response);
    }

    // Logout and Revoke Current Session
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request) {

        String accessToken = extractBearerToken(request);

        if (accessToken == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message", "A valid Bearer token is required"
                    ));
        }

        boolean revoked = sessionService.revokeSession(accessToken);

        if (!revoked) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message",
                            "Session is already revoked or does not exist"
                    ));
        }

        return ResponseEntity.ok(Map.of(
                "message", "Logout successful"
        ));
    }

    // Get Pending Staff Accounts - ADMIN Only
    @GetMapping("/users/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PendingStaffUserResponse>> getPendingStaffUsers() {

        List<PendingStaffUserResponse> users =
                staffUserService.getPendingStaffUsers();

        return ResponseEntity.ok(users);
    }

    // Extract Bearer Token
    private String extractBearerToken(HttpServletRequest request) {

        String authorizationHeader =
                request.getHeader("Authorization");

        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }

        String token = authorizationHeader.substring(7).trim();

        return token.isBlank() ? null : token;
    }
}
