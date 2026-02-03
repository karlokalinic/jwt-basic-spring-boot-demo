package com.example.jwtapp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class NoCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
            @Override
            public void addCookie(Cookie cookie) {
                // Intentionally ignore any cookies.
            }

            @Override
            public void addHeader(String name, String value) {
                if ("Set-Cookie".equalsIgnoreCase(name)) {
                    return;
                }
                super.addHeader(name, value);
            }

            @Override
            public void setHeader(String name, String value) {
                if ("Set-Cookie".equalsIgnoreCase(name)) {
                    return;
                }
                super.setHeader(name, value);
            }
        };

        filterChain.doFilter(request, wrapper);
    }
}
