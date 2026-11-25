package com.careflow.authentication_service.service;

import com.careflow.authentication_service.dto.request.CreateStaffUserRequest;
import com.careflow.authentication_service.dto.response.CreateStaffUserResponse;
import com.careflow.authentication_service.entity.Role;
import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.repository.RoleRepository;
import com.careflow.authentication_service.repository.UserRepository;
import com.careflow.authentication_service.dto.response.PendingStaffUserResponse;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.List;

@Service
public class StaffUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;

    private static final Set<String> ALLOWED_STAFF_ROLES =
            Set.of("DOCTOR", "ASSISTANT", "LAB_TECHNICIAN");

    public StaffUserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            SessionService sessionService) {

        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
    }

    // Staff Self-Registration
    @Transactional
    public CreateStaffUserResponse createStaffUser(
            CreateStaffUserRequest request) {

        String email = request.email()
                .trim()
                .toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(
                    "An account with this email already exists"
            );
        }

        String roleName = request.role()
                .trim()
                .toUpperCase(Locale.ROOT);

        if (!ALLOWED_STAFF_ROLES.contains(roleName)) {
            throw new IllegalArgumentException(
                    "Registration is allowed only for DOCTOR, ASSISTANT and LAB_TECHNICIAN"
            );
        }

        if (request.password()
                .getBytes(StandardCharsets.UTF_8).length > 72) {

            throw new IllegalArgumentException(
                    "Password cannot exceed 72 UTF-8 bytes"
            );
        }

        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Requested role does not exist"
                ));

        String hashedPassword =
                passwordEncoder.encode(request.password());

        User user = User.builder()
                .fullName(request.fullName().trim())
                .email(email)
                .password(hashedPassword)
                .role(role)
                .enabled(false)
                .pendingApproval(true)
                .build();

        User savedUser = userRepository.save(user);

        return new CreateStaffUserResponse(
                savedUser.getId(),
                savedUser.getFullName(),
                savedUser.getEmail(),
                savedUser.getRole().getName(),
                "Registration successful. Your account is pending ADMIN approval."
        );
    }

    // Approve Staff Account - ADMIN Only
    @Transactional
    public void approveStaffUser(Long userId) {

        User user = findStaffUser(userId);

        if (!Boolean.TRUE.equals(user.getPendingApproval())) {
            throw new IllegalArgumentException(
                    "This account is not pending approval"
            );
        }

        user.setPendingApproval(false);
        user.setEnabled(true);

        userRepository.save(user);
    }

    // Deactivate Staff Account - ADMIN Only
    @Transactional
    public void deactivateStaffUser(Long userId) {

        User user = findStaffUser(userId);

        if (Boolean.FALSE.equals(user.getEnabled())
                && Boolean.FALSE.equals(user.getPendingApproval())) {

            throw new IllegalArgumentException(
                    "This staff account is already inactive"
            );
        }

        // Prevent future approval of this account
        user.setPendingApproval(false);
        user.setEnabled(false);

        userRepository.save(user);

        // Revoke all active sessions
        int revokedSessions =
                sessionService.revokeAllActiveSessions(userId);

        System.out.println(
                "Staff account " + userId
                + " deactivated. Revoked sessions: "
                + revokedSessions
        );
    }

    // Find and Validate Staff Account
    private User findStaffUser(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Staff account not found"
                ));

        String roleName = user.getRole()
                .getName()
                .toUpperCase(Locale.ROOT);

        if ("ADMIN".equals(roleName)) {
            throw new IllegalArgumentException(
                    "ADMIN account cannot be modified"
            );
        }

        if (!ALLOWED_STAFF_ROLES.contains(roleName)) {
            throw new IllegalArgumentException(
                    "This account is not a staff account"
            );
        }

        return user;
    }


    // Get Pending Staff Accounts - ADMIN Only
    @Transactional(readOnly = true)
    public List<PendingStaffUserResponse> getPendingStaffUsers() {

        return userRepository.findAllByPendingApprovalTrue()
                .stream()
                .map(user -> new PendingStaffUserResponse(
                        user.getId(),
                        user.getFullName(),
                        user.getEmail(),
                        user.getRole().getName(),
                        user.getCreatedAt()
                ))
                .toList();
    }
}
