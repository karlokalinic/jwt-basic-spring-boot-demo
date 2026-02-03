package com.example.jwtapp.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Tiny "app": a notes list.
 * - Public ping
 * - Protected notes (ROLE_USER)
 * - Admin secret (ROLE_ADMIN)
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final List<String> notes = new CopyOnWriteArrayList<>(List.of(
            "Prva bilješka: 'Ne vjeruj tokenu koji traje vječno.'",
            "Druga bilješka: 'Stateless je zen, ali i odgovornost.'"
    ));

    @GetMapping("/public/ping")
    public String ping() {
        return "pong";
    }

    @GetMapping("/notes")
    @PreAuthorize("hasRole('USER')")
    public List<String> getNotes(Authentication auth) {
        // auth.getName() is the username from the token (or from the security context)
        return notes.stream().map(n -> auth.getName() + " vidi: " + n).toList();
    }

    @PostMapping("/notes")
    @PreAuthorize("hasRole('USER')")
    public List<String> addNote(@RequestBody String note, Authentication auth) {
        notes.add("[" + auth.getName() + "] " + note);
        return notes;
    }

    @GetMapping("/admin/secret")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminSecret() {
        return "Ovo vidi samo ADMIN. Ako ovo vidi student -> bug. 🫠";
    }
}
