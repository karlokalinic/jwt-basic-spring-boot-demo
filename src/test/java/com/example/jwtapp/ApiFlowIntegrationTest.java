package com.example.jwtapp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ApiFlowIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @Value("${app.jwt.secret}") String secret;

    private String loginAndGetToken(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("token").asText();
    }

    private String buildExpiredTokenForStudent() {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject("student")
                .setIssuedAt(Date.from(now.minusSeconds(60)))
                .setExpiration(Date.from(now.minusSeconds(1))) // expired
                .claim("rol", List.of("ROLE_USER"))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void ping_is_public() throws Exception {
        mockMvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    void index_html_is_public() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(containsString("JWT UI Demo")));
    }

    @Test
    void login_rejects_blank_fields() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_rejects_wrong_password() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"student\",\"password\":\"nope\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void notes_requires_token() throws Exception {
        mockMvc.perform(get("/api/notes"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void student_can_read_and_write_notes_but_cant_open_admin() throws Exception {
        String token = loginAndGetToken("student", "pass123");

        mockMvc.perform(get("/api/notes")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isArray());

        mockMvc.perform(post("/api/notes")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("nova bilješka iz testa"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());

        mockMvc.perform(get("/api/admin/secret")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_can_open_admin_secret() throws Exception {
        String token = loginAndGetToken("admin", "admin123");

        mockMvc.perform(get("/api/admin/secret")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ADMIN")));
    }

    @Test
    void malformed_or_expired_token_never_crashes_app() throws Exception {
        // Malformed -> should NOT be 500, should be 401
        mockMvc.perform(get("/api/notes")
                        .header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized());

        // Expired -> also 401
        String expired = buildExpiredTokenForStudent();
        mockMvc.perform(get("/api/notes")
                        .header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());

        // Garbage token on PUBLIC endpoint should still return OK
        mockMvc.perform(get("/api/public/ping")
                        .header("Authorization", "Bearer " + expired))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }
}
