package com.example.jwtapp.api;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/sql")
public class SqlInjectionController {

    private final JdbcTemplate jdbcTemplate;

    public SqlInjectionController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/vuln")
    @PreAuthorize("hasRole('USER')")
    public List<Map<String, Object>> vulnerableLookup(@RequestParam String username) {
        String sql = "SELECT id, username, role FROM demo_users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }

    @GetMapping("/safe")
    @PreAuthorize("hasRole('USER')")
    public List<Map<String, Object>> safeLookup(@RequestParam String username) {
        String sql = "SELECT id, username, role FROM demo_users WHERE username = ?";
        return jdbcTemplate.queryForList(sql, username);
    }
}
