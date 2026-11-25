package com.careflow.authentication_service.config;

import com.careflow.authentication_service.entity.Role;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.repository.RoleRepository;
import com.careflow.authentication_service.repository.UserRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

@Configuration
public class DataInitializer {

    private static final Logger log =
            LoggerFactory.getLogger(DataInitializer.class);

    @Value("${app.admin.bootstrap.enabled:false}")
    private boolean adminBootstrapEnabled;

    @Value("${app.admin.bootstrap.full-name:}")
    private String adminFullName;

    @Value("${app.admin.bootstrap.email:}")
    private String adminEmail;

    @Value("${app.admin.bootstrap.password:}")
    private String adminPassword;

    @Bean
    CommandLineRunner initializeRoles(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {

        return args -> {

            // Initialize system roles
            String[] roleNames = {
                    "PATIENT",
                    "DOCTOR",
                    "ASSISTANT",
                    "LAB_TECHNICIAN",
                    "ADMIN"
            };

            for (String roleName : roleNames) {

                if (roleRepository.findByName(roleName).isEmpty()) {

                    Role role = Role.builder()
                            .name(roleName)
                            .build();

                    roleRepository.save(role);

                    log.info("Created role: {}", roleName);
                }
            }

            log.info("CareFlow roles initialized successfully.");

            // Check existing ADMIN accounts
            long adminCount =
                    userRepository.countByRole_Name("ADMIN");

            if (adminCount > 1) {
                throw new IllegalStateException(
                        "Multiple ADMIN accounts detected. "
                        + "Only one ADMIN account is allowed."
                );
            }

            // Skip bootstrap if ADMIN already exists
            if (adminCount == 1) {
                log.info("ADMIN account already exists. Bootstrap skipped.");
                return;
            }

            // Bootstrap must be explicitly enabled
            if (!adminBootstrapEnabled) {
                log.info("ADMIN bootstrap is disabled.");
                return;
            }

            // Validate bootstrap details
            if (adminFullName == null || adminFullName.isBlank()
                    || adminEmail == null || adminEmail.isBlank()
                    || adminPassword == null || adminPassword.isBlank()) {

                throw new IllegalStateException(
                        "ADMIN bootstrap details are incomplete."
                );
            }

            String normalizedEmail = adminEmail
                    .trim()
                    .toLowerCase(Locale.ROOT);

            if (userRepository.existsByEmail(normalizedEmail)) {
                throw new IllegalStateException(
                        "The configured ADMIN email is already in use."
                );
            }

            int passwordBytes = adminPassword
                    .getBytes(StandardCharsets.UTF_8).length;

            if (adminPassword.length() < 8 || passwordBytes > 72) {
                throw new IllegalStateException(
                        "ADMIN password must be at least 8 characters "
                        + "and no more than 72 UTF-8 bytes."
                );
            }

            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseThrow(() -> new IllegalStateException(
                            "ADMIN role was not initialized."
                    ));

            // Create initial ADMIN account
            User admin = User.builder()
                    .fullName(adminFullName.trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .role(adminRole)
                    .enabled(true)
                    .pendingApproval(false)
                    .build();

            userRepository.save(admin);

            log.info("Initial ADMIN account created successfully.");
        };
    }
}
