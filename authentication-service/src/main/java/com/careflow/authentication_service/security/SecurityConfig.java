package com.careflow.authentication_service.security;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
            // Disable CSRF protection for REST APIs
            .csrf(csrf -> csrf.disable())

            // Disable default login form
            .formLogin(form -> form.disable())

            // Disable HTTP Basic authentication
            .httpBasic(basic -> basic.disable())

            // Return JSON response for unauthorized requests
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((request, response, authException) -> {

                    response.setStatus(
                        HttpServletResponse.SC_UNAUTHORIZED
                    );

                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");

                    response.getWriter().write(
                        "{\"status\":401,"
                        + "\"error\":\"Unauthorized\","
                        + "\"message\":\"Please provide a valid JWT token\"}"
                    );
                })
            )

            // Stateless authentication
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Endpoint authorization
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/auth/register",
                    "/api/auth/login"
                ).permitAll()

                .anyRequest().authenticated()
            )

            // Register JWT authentication filter
            .addFilterBefore(
                jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
