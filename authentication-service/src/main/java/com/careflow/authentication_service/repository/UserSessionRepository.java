package com.careflow.authentication_service.repository;

import com.careflow.authentication_service.entity.UserSession;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserSessionRepository
        extends JpaRepository<UserSession, Long> {

    // Find session using hashed JWT token
    Optional<UserSession> findByTokenHash(String tokenHash);

    // Revoke all active sessions belonging to a user
    @Modifying(
            clearAutomatically = true,
            flushAutomatically = true
    )
    @Query("""
            UPDATE UserSession s
            SET s.revoked = true
            WHERE s.user.id = :userId
            AND s.revoked = false
            """)
    int revokeAllActiveSessionsByUserId(
            @Param("userId") Long userId
    );
}
