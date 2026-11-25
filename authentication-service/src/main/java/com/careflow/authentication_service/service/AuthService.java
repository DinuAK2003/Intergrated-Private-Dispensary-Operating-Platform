package com.careflow.authentication_service.service;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.exception.InvalidCredentialsException;
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

    // Staff Login
    @Transactional
    public LoginResponse login(LoginRequest request) {

        // Find user by email
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new InvalidCredentialsException(
                        "Invalid email or password"
                ));

        // Verify password
        if (!passwordEncoder.matches(
                request.password(),
                user.getPassword())) {

            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        // Check whether the account is enabled
        if (!Boolean.TRUE.equals(user.getEnabled())) {

            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        // Generate JWT access token
        String accessToken = jwtService.generateToken(user);

        // Extract exact token expiration time
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

        // Return login response
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
