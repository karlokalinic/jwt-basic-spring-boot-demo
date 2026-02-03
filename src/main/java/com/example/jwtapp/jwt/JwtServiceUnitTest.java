package com.example.jwtapp.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceUnitTest {

    private static final String SECRET = "change-me-change-me-change-me-change-me!";
    private static final long EXP_MINUTES = 15;
    private static final String ISSUER = "secure-api";
    private static final String AUDIENCE = "secure-app";

    @Test
    void generated_token_contains_username_and_roles_and_is_valid_for_same_user() {
        JwtService jwt = new JwtService(SECRET, EXP_MINUTES, ISSUER, AUDIENCE);

        UserDetails user = User.withUsername("student")
                .password("ignored")
                .roles("USER")
                .build();

        String token = jwt.generateToken(user);

        assertEquals("student", jwt.extractUsername(token));
        assertTrue(jwt.extractRoles(token).contains("ROLE_USER"));
        assertTrue(jwt.isTokenValid(token, user));

        UserDetails other = User.withUsername("someoneElse").password("x").roles("USER").build();
        assertFalse(jwt.isTokenValid(token, other));
    }

    @Test
    void roles_extraction_returns_empty_when_claim_is_wrong_type() {
        JwtService jwt = new JwtService(SECRET, EXP_MINUTES, ISSUER, AUDIENCE);

        String weirdToken = Jwts.builder()
                .setSubject("student")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(60)))
                // wrong type on purpose: rol should be a List, but we set a String
                .claim("rol", "ROLE_USER")
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        assertEquals("student", jwt.extractUsername(weirdToken));
        assertTrue(jwt.extractRoles(weirdToken).isEmpty());
    }
}
