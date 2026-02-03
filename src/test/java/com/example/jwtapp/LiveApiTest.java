package com.example.jwtapp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live API testovi - koriste pravi HTTP klijent da pozovu running server.
 * Ovi testovi se mogu pokretati iz UI-a jer NE koriste @SpringBootTest.
 */
class LiveApiTest {

    // Automatski detektiraj URL - koristi localhost ili Render URL
    private static final String BASE_URL = detectBaseUrl();
    private static final String SECRET = "change-me-change-me-change-me-change-me!";
    private static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private static final ObjectMapper mapper = new ObjectMapper();

    private static String detectBaseUrl() {
        // Prvo provjeri system property
        String prop = System.getProperty("test.baseUrl");
        if (prop != null && !prop.isBlank()) return prop;
        
        // Provjeri environment varijablu (Render postavlja RENDER_EXTERNAL_URL)
        String renderUrl = System.getenv("RENDER_EXTERNAL_URL");
        if (renderUrl != null && !renderUrl.isBlank()) return renderUrl;
        
        // Provjeri PORT environment varijablu
        String port = System.getenv("PORT");
        if (port != null && !port.isBlank()) {
            return "http://localhost:" + port;
        }
        
        // Default
        return "http://localhost:8080";
    }

    // ═══════════════════════════════════════════════════════════════
    // HELPER METODE
    // ═══════════════════════════════════════════════════════════════

    private static String login(String username, String password) throws Exception {
        String body = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/api/auth/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Login failed: " + response.statusCode());
        }
        JsonNode json = mapper.readTree(response.body());
        return json.get("token").asText();
    }

    private static HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + path))
                .GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String buildExpiredToken() {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject("student")
                .setIssuedAt(Date.from(now.minusSeconds(60)))
                .setExpiration(Date.from(now.minusSeconds(1)))
                .claim("rol", List.of("USER"))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    // ═══════════════════════════════════════════════════════════════
    // PUBLIC ENDPOINT TESTOVI
    // ═══════════════════════════════════════════════════════════════

    @Test
    void ping_is_public() throws Exception {
        HttpResponse<String> response = get("/api/public/ping", null);
        assertEquals(200, response.statusCode(), "Ping endpoint mora biti javan");
        assertEquals("pong", response.body());
    }

    @Test
    void index_html_is_public() throws Exception {
        HttpResponse<String> response = get("/", null);
        assertEquals(200, response.statusCode(), "Index mora biti javan");
        assertTrue(response.body().contains("<!DOCTYPE html") || response.body().contains("<html"),
                "Mora vratiti HTML");
    }

    // ═══════════════════════════════════════════════════════════════
    // AUTORIZACIJA TESTOVI
    // ═══════════════════════════════════════════════════════════════

    @Test
    void notes_requires_token() throws Exception {
        HttpResponse<String> response = get("/api/notes", null);
        assertEquals(401, response.statusCode(), "Notes bez tokena mora vratiti 401");
    }

    @Test
    void admin_can_open_admin_secret() throws Exception {
        String token = login("admin", "admin123");
        HttpResponse<String> response = get("/api/admin/secret", token);
        assertEquals(200, response.statusCode(), "Admin mora moći pristupiti /api/admin/secret");
        assertTrue(response.body().toUpperCase().contains("ADMIN"), "Odgovor mora sadržavati 'ADMIN'");
    }

    @Test
    void student_cannot_access_admin() throws Exception {
        String token = login("student", "pass123");
        HttpResponse<String> response = get("/api/admin/secret", token);
        assertEquals(403, response.statusCode(), "Student NE smije pristupiti admin endpointu");
    }

    // ═══════════════════════════════════════════════════════════════
    // OTPORNOST TESTOVI
    // ═══════════════════════════════════════════════════════════════

    @Test
    void malformed_token_returns_401_not_500() throws Exception {
        HttpResponse<String> response = get("/api/notes", "abc.def.ghi");
        assertTrue(response.statusCode() == 401 || response.statusCode() == 403,
                "Malformirani token mora vratiti 401/403, ne 500. Dobiveno: " + response.statusCode());
    }

    @Test
    void expired_token_returns_401() throws Exception {
        String expired = buildExpiredToken();
        HttpResponse<String> response = get("/api/notes", expired);
        assertEquals(401, response.statusCode(), "Istekli token mora vratiti 401");
    }

    @Test
    void bad_token_on_public_endpoint_still_works() throws Exception {
        HttpResponse<String> response = get("/api/public/ping", "garbage-token");
        assertEquals(200, response.statusCode(), "Public endpoint mora raditi čak i s lošim tokenom");
    }
}
