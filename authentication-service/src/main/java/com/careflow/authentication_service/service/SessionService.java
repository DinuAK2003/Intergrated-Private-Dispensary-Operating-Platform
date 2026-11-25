package com.careflow.authentication_service.service;

import com.careflow.authentication_service.entity.User;
import com.careflow.authentication_service.entity.UserSession;
import com.careflow.authentication_service.repository.UserSessionRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Service
public class SessionService {

    private final UserSessionRepository userSessionRepository;

    public SessionService(
            UserSessionRepository userSessionRepository) {

        this.userSessionRepository = userSessionRepository;
    }

    // Create a new user session
    @Transactional
    public void createSession(
            User user,
            String accessToken,
            LocalDateTime expiresAt) {

        String tokenHash = hashToken(accessToken);

        UserSession session = UserSession.builder()
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();

        userSessionRepository.save(session);
    }

    // Validate an existing session
    @Transactional(readOnly = true)
    public boolean isSessionValid(String accessToken) {

        String tokenHash = hashToken(accessToken);

        return userSessionRepository.findByTokenHash(tokenHash)
                .filter(session ->
                        Boolean.FALSE.equals(session.getRevoked()))
                .filter(session ->
                        session.getExpiresAt().isAfter(
                                LocalDateTime.now()))
                .filter(session ->
                        Boolean.TRUE.equals(
                                session.getUser().getEnabled()))
                .isPresent();
    }

    // Revoke an individual session during logout
    @Transactional
    public boolean revokeSession(String accessToken) {

        String tokenHash = hashToken(accessToken);

        UserSession session = userSessionRepository
                .findByTokenHash(tokenHash)
                .orElse(null);

        if (session == null
                || Boolean.TRUE.equals(session.getRevoked())) {
            return false;
        }

        session.setRevoked(true);
        userSessionRepository.save(session);

        return true;
    }

    // Revoke all active sessions of a user
    @Transactional
    public int revokeAllActiveSessions(Long userId) {

        return userSessionRepository
                .revokeAllActiveSessionsByUserId(userId);
    }

    // Generate SHA-256 hash of JWT
    private String hashToken(String token) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    token.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException exception) {

            throw new IllegalStateException(
                    "SHA-256 algorithm is not available",
                    exception
            );
        }
    }
}
