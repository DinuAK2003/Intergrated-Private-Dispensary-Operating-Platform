package com.careflow.authentication_service.config;

import com.careflow.authentication_service.entity.Role;
import com.careflow.authentication_service.repository.RoleRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initializeRoles(
            RoleRepository roleRepository) {

        return args -> {

            String[] roleNames = {
                    "PATIENT",
                    "DOCTOR",
                    "ASSISTANT",
                    "LAB_TECHNICIAN"
            };

            for (String roleName : roleNames) {

                if (roleRepository.findByName(roleName).isEmpty()) {

                    Role role = Role.builder()
                            .name(roleName)
                            .build();

                    roleRepository.save(role);
                }
            }

            System.out.println(
                    "CareFlow roles initialized successfully."
            );
        };
    }
}
