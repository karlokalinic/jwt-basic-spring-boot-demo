package com.example.jwtapp.testing;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class TestCatalog {

    // NAPOMENA: Koristimo LiveApiTest (HTTP client) umjesto ApiFlowIntegrationTest (MockMvc)
    // jer se MockMvc ne može pokrenuti unutar već pokrenute Spring aplikacije.
    
    private static final List<TestCase> CASES = List.of(
            new TestCase(
                    "public-ping",
                    "Public ping je otvoren",
                    "Public endpointi",
                    "Potvrđuje da /api/public/ping ne traži autentifikaciju.",
                    List.of("Pozovi /api/public/ping bez Authorization headera."),
                    List.of("HTTP 200", "Odgovor: pong"),
                    "com.example.jwtapp.LiveApiTest",
                    "ping_is_public"
            ),
            new TestCase(
                    "public-index-html",
                    "Index stranica je javna",
                    "Public endpointi",
                    "Provjerava da UI nije zaključan i da se vraća HTML.",
                    List.of("Pozovi GET / bez tokena."),
                    List.of("HTTP 200", "Content-Type: text/html"),
                    "com.example.jwtapp.LiveApiTest",
                    "index_html_is_public"
            ),
            new TestCase(
                    "notes-require-token",
                    "Notes endpoint zahtijeva token",
                    "Autorizacija",
                    "Bez JWT-a nema pristupa korisničkim resursima.",
                    List.of("GET /api/notes bez Authorization headera."),
                    List.of("HTTP 401"),
                    "com.example.jwtapp.LiveApiTest",
                    "notes_requires_token"
            ),
            new TestCase(
                    "student-cant-admin",
                    "Student nema pristup admin endpointu",
                    "Autorizacija",
                    "Student (ROLE_USER) ne smije pristupiti /api/admin/secret.",
                    List.of("Login kao student", "GET /api/admin/secret"),
                    List.of("HTTP 403"),
                    "com.example.jwtapp.LiveApiTest",
                    "student_cannot_access_admin"
            ),
            new TestCase(
                    "admin-secret",
                    "Admin vidi secret",
                    "Autorizacija",
                    "Admin role mora imati pristup tajnom endpointu.",
                    List.of("Login kao admin", "GET /api/admin/secret"),
                    List.of("HTTP 200", "Sadrži ADMIN"),
                    "com.example.jwtapp.LiveApiTest",
                    "admin_can_open_admin_secret"
            ),
            new TestCase(
                    "malformed-token",
                    "Malformirani token vraća 401",
                    "Otpornost",
                    "Aplikacija mora vratiti 401, ne 500, za loše JWT-ove.",
                    List.of("GET /api/notes s krivim tokenom"),
                    List.of("HTTP 401 ili 403"),
                    "com.example.jwtapp.LiveApiTest",
                    "malformed_token_returns_401_not_500"
            ),
            new TestCase(
                    "expired-token",
                    "Istekli token vraća 401",
                    "Otpornost",
                    "Token koji je istekao mora biti odbijen.",
                    List.of("Stvori token s prošlim expiration", "GET /api/notes"),
                    List.of("HTTP 401"),
                    "com.example.jwtapp.LiveApiTest",
                    "expired_token_returns_401"
            ),
            new TestCase(
                    "bad-token-public",
                    "Loš token ne blokira public endpoint",
                    "Otpornost",
                    "Public endpoint mora raditi čak i ako je token neispravan.",
                    List.of("GET /api/public/ping s garbage tokenom"),
                    List.of("HTTP 200"),
                    "com.example.jwtapp.LiveApiTest",
                    "bad_token_on_public_endpoint_still_works"
            ),
            new TestCase(
                    "jwt-claims",
                    "JWT sadrži ispravan subject i role",
                    "JWT unit",
                    "Jedinični test JwtService-a: claims + validacija korisnika.",
                    List.of("Generiraj token za usera", "Provjeri subject i role", "Validiraj token"),
                    List.of("Subject=student", "ROLE_USER prisutan", "Token validan samo za tog korisnika"),
                    "com.example.jwtapp.jwt.JwtServiceUnitTest",
                    "generated_token_contains_username_and_roles_and_is_valid_for_same_user"
            ),
            new TestCase(
                    "jwt-roles-type",
                    "Krivi tip claim-a ne ruši parser",
                    "JWT unit",
                    "Ako je rol claim krivog tipa, parser vraća praznu listu.",
                    List.of("Stvori token gdje je rol claim String"),
                    List.of("extractRoles vraća prazno"),
                    "com.example.jwtapp.jwt.JwtServiceUnitTest",
                    "roles_extraction_returns_empty_when_claim_is_wrong_type"
            )
    );

    private static final Map<String, TestCase> BY_ID = CASES.stream()
            .collect(Collectors.toMap(TestCase::id, item -> item));

    private TestCatalog() {
    }

    public static List<TestCase> cases() {
        return CASES;
    }

    public static TestCase byId(String id) {
        return BY_ID.get(id);
    }
}
