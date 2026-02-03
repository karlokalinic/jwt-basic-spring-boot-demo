package com.example.jwtapp.api;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class SqlDemoService {

    private final JdbcTemplate jdbcTemplate;
    private final NamedParameterJdbcTemplate namedJdbcTemplate;

    public SqlDemoService(JdbcTemplate jdbcTemplate, NamedParameterJdbcTemplate namedJdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.namedJdbcTemplate = namedJdbcTemplate;
    }

    public List<Map<String, Object>> vulnerableFindByUsername(String username) {
        String sql = "SELECT id, username, full_name, email, role FROM demo_users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }

    public List<Map<String, Object>> safeFindByUsername(String username) {
        String sql = "SELECT id, username, full_name, email, role FROM demo_users WHERE username = :username";
        return namedJdbcTemplate.queryForList(sql, Map.of("username", username));
    }
}
