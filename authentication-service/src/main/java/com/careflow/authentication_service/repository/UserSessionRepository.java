package com.careflow.authentication_service.repository;

import com.careflow.authentication_service.entity.UserSession;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserSessionRepository
        extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findByTokenHash(String tokenHash);

}
