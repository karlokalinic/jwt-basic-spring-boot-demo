package com.example.jwtapp.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final Key signingKey;
    private final long expMinutes;
    private final String issuer;
    private final String audience;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expMinutes}") long expMinutes,
            @Value("${app.jwt.issuer}") String issuer,
            @Value("${app.jwt.audience}") String audience
    ) {
        // HS256 requires 256-bit (32-byte) key min.
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expMinutes = expMinutes;
        this.issuer = issuer;
        this.audience = audience;
    }

    public String generateToken(UserDetails user) {
        // Izvuci role BEZ "ROLE_" prefiksa - filter će ga dodati nazad
        List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.startsWith("ROLE_") ? role.substring(5) : role)
                .collect(Collectors.toList());

        Instant now = Instant.now();
        Instant exp = now.plus(expMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuer(issuer)
                .setAudience(audience)
                .setSubject(user.getUsername())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .claim("rol", roles) // ["USER", "ADMIN"] - bez ROLE_ prefiksa
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Izvlači role iz tokena. Robustan na različite tipove claim-a.
     * - Ako je List<String> → vraća listu
     * - Ako je String → vraća listu s jednim elementom
     * - Ako je null ili drugi tip → vraća praznu listu
     */
    
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        Object raw = claims.get("rol");
        
        if (raw == null) {
            return List.of();
        }
        
        // Ako je već String (pojedinačna rola)
        if (raw instanceof String s) {
            return s.isBlank() ? List.of() : List.of(s);
        }
        
        // Ako je Collection (očekivano)
        if (raw instanceof java.util.Collection<?> c) {
            return c.stream()
                    .filter(item -> item != null)
                    .map(String::valueOf)
                    .filter(s -> !s.isBlank())
                    .toList();
        }
        
        // Nepoznat tip - vrati prazno (sigurnije od bacanja exceptiona)
        return List.of();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date exp = extractAllClaims(token).getExpiration();
        return exp.before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
