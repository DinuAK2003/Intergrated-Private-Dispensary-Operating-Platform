package com.careflow.authentication_service.controller;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.request.RegisterRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.dto.response.RegisterResponse;
import com.careflow.authentication_service.service.AuthService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.core.Authentication;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request) {

        RegisterResponse response =
                authService.register(request, "ASSISTANT");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request) {

        LoginResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

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
}
