package com.careflow.authentication_service.controller;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.service.AuthService;
import com.careflow.authentication_service.service.SessionService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final SessionService sessionService;

    public AuthController(
            AuthService authService,
            SessionService sessionService) {

        this.authService = authService;
        this.sessionService = sessionService;
    }

    // Staff Login
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request) {

        LoginResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    // Get Current Authenticated User
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            Authentication authentication) {

        Map<String, Object> response = Map.of(
                "email", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "message", "Authentication successful"
        );

        return ResponseEntity.ok(response);
    }

    // Logout and Revoke Current Session
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request) {

        String authorizationHeader =
                request.getHeader("Authorization");

        // Validate Authorization header
        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")
                || authorizationHeader.substring(7).isBlank()) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message",
                            "A valid Bearer token is required"
                    ));
        }

        // Extract access token
        String accessToken =
                authorizationHeader.substring(7).trim();

        // Revoke current session
        boolean revoked =
                sessionService.revokeSession(accessToken);

        if (!revoked) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message",
                            "Session is already revoked or does not exist"
                    ));
        }

        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "Logout successful"
                )
        );
    }
}
