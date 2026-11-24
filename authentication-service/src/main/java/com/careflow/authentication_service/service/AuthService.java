package com.careflow.authentication_service.service;

import com.careflow.authentication_service.dto.request.LoginRequest;
import com.careflow.authentication_service.dto.request.RegisterRequest;
import com.careflow.authentication_service.dto.response.LoginResponse;
import com.careflow.authentication_service.dto.response.RegisterResponse;
import com.careflow.authentication_service.entity.Role;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.repository.RoleRepository;
import com.careflow.authentication_service.repository.UserRepository;
import com.careflow.authentication_service.security.JwtService;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {

        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public RegisterResponse register(RegisterRequest request, String roleName) {

        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException(
                    "Email is already registered"
            );
        }

        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found: " + roleName
                ));

        User user = User.builder()
                .fullName(request.fullName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(role)
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);

        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getFullName(),
                savedUser.getEmail(),
                savedUser.getRole().getName(),
                "Registration successful"
        );
    }

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

        String accessToken = jwtService.generateToken(user);

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
