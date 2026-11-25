package com.careflow.authentication_service;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.exception.InvalidCredentialsException;
import com.careflow.authentication_service.repository.UserRepository;
import com.careflow.authentication_service.service.AuthService;
import com.careflow.authentication_service.service.SessionService;
import com.careflow.authentication_service.security.JwtService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@SpringBootTest
class AuthenticationServiceApplicationTests {

    @Autowired
    private AuthService authService;

    @MockitoBean
	private PasswordEncoder passwordEncoder;

    @MockitoBean
	private UserRepository userRepository;

	@MockitoBean
	private JwtService jwtService;

	@MockitoBean
	private SessionService sessionService;

    @Test
    void contextLoads() {
        assertNotNull(authService);
    }

    @Test
    void successfulLoginTest() {

        LoginRequest request = new LoginRequest(
                "receptionist@example.com",
                "CareFlowTest@2026"
        );

        User user = createTestUser(true);

        when(userRepository.findByEmail(request.email()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(
                request.password(), user.getPassword()))
                .thenReturn(true);

        when(jwtService.generateToken(user))
                .thenReturn("test.jwt.token");

        when(jwtService.extractExpiration("test.jwt.token"))
                .thenReturn(new java.util.Date(
                        System.currentTimeMillis() + 900000
                ));

        LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("receptionist@example.com", response.email());
        assertEquals("Test Receptionist", response.fullName());
        assertEquals("ASSISTANT", response.role());
        assertEquals("test.jwt.token", response.accessToken());
        assertEquals("Bearer", response.tokenType());

        verify(sessionService).createSession(
                eq(user), eq("test.jwt.token"), any()
        );
    }

    @Test
    void invalidPasswordTest() {

        LoginRequest request = new LoginRequest(
                "receptionist@example.com",
                "WrongPassword123"
        );

        User user = createTestUser(true);

        when(userRepository.findByEmail(request.email()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(
                request.password(), user.getPassword()))
                .thenReturn(false);

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(sessionService, never())
                .createSession(any(), anyString(), any());
    }

    @Test
    void disabledAccountLoginTest() {

        LoginRequest request = new LoginRequest(
                "disabled@example.com",
                "CorrectPassword123"
        );

        User user = createTestUser(false);
        user.setEmail("disabled@example.com");

        when(userRepository.findByEmail(request.email()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(
                request.password(), user.getPassword()))
                .thenReturn(true);

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(sessionService, never())
                .createSession(any(), anyString(), any());
    }

    private User createTestUser(boolean enabled) {

        com.careflow.authentication_service.entity.Role role =
                com.careflow.authentication_service.entity.Role.builder()
                        .id(3L)
                        .name("ASSISTANT")
                        .build();

        return User.builder()
                .id(1L)
                .fullName("Test Receptionist")
                .email("receptionist@example.com")
                .password("encoded-test-password")
                .role(role)
                .enabled(enabled)
                .build();
    }
}
