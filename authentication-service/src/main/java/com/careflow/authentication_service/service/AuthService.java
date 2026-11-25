package com.careflow.authentication_service.service;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.repository.UserRepository;
import com.careflow.authentication_service.security.JwtService;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final SessionService sessionService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            SessionService sessionService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.sessionService = sessionService;
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Invalid email or password"
                ));

        if (!passwordEncoder.matches(
                request.password(),
                user.getPassword())) {

            throw new IllegalArgumentException(
                    "Invalid email or password"
            );
        }

        if (!Boolean.TRUE.equals(user.getEnabled())) {
            throw new IllegalArgumentException(
                    "User account is disabled"
            );
        }

        // Generate JWT access token
        String accessToken = jwtService.generateToken(user);

        // Extract the exact expiration time from the JWT
        LocalDateTime expiresAt = jwtService.extractExpiration(accessToken)
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        // Store only the hashed token in the database
        sessionService.createSession(
                user,
                accessToken,
                expiresAt
        );

        return new LoginResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().getName(),
                accessToken,
                "Bearer",
                "Login successful"
        );
    }
}