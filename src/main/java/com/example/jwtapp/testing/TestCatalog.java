package com.example.jwtapp.testing;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class TestCatalog {

    private static final List<TestCase> CASES = List.of(
            new TestCase(
                    "public-ping",
                    "Public ping je otvoren",
                    "Public endpointi",
                    "Potvrđuje da /api/public/ping ne traži autentifikaciju.",
                    List.of("Pozovi /api/public/ping bez Authorization headera."),
                    List.of("HTTP 200", "Odgovor: pong"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "ping_is_public"
            ),
            new TestCase(
                    "public-index-html",
                    "Index stranica je javna",
                    "Public endpointi",
                    "Provjerava da UI nije zaključan i da se vraća HTML.",
                    List.of("Pozovi GET / bez tokena."),
                    List.of("HTTP 200", "Content-Type: text/html"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "index_html_is_public"
            ),
            new TestCase(
                    "auth-blank-fields",
                    "Login odbija prazna polja",
                    "Autentifikacija",
                    "Validacija ulaza mora spriječiti prazne vrijednosti.",
                    List.of("POST /api/auth/login sa praznim username/password poljima."),
                    List.of("HTTP 400", "Greška validacije"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "login_rejects_blank_fields"
            ),
            new TestCase(
                    "auth-wrong-password",
                    "Login odbija krivu lozinku",
                    "Autentifikacija",
                    "Provjera da lozinka mora biti točna.",
                    List.of("POST /api/auth/login s krivom lozinkom."),
                    List.of("HTTP 401", "Nema tokena"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "login_rejects_wrong_password"
            ),
            new TestCase(
                    "notes-require-token",
                    "Notes endpoint zahtijeva token",
                    "Autorizacija",
                    "Bez JWT-a nema pristupa korisničkim resursima.",
                    List.of("GET /api/notes bez Authorization headera."),
                    List.of("HTTP 401"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "notes_requires_token"
            ),
            new TestCase(
                    "student-notes-admin",
                    "Student ima notes, ali ne admin",
                    "Autorizacija",
                    "Student može čitati/pisati notes, ali ne može admin secret.",
                    List.of(
                            "Login kao student",
                            "GET /api/notes",
                            "POST /api/notes",
                            "GET /api/admin/secret"
                    ),
                    List.of("Notes: HTTP 200", "Admin secret: HTTP 403"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "student_can_read_and_write_notes_but_cant_open_admin"
            ),
            new TestCase(
                    "admin-secret",
                    "Admin vidi secret",
                    "Autorizacija",
                    "Admin role mora imati pristup tajnom endpointu.",
                    List.of("Login kao admin", "GET /api/admin/secret"),
                    List.of("HTTP 200", "Sadrži ADMIN"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "admin_can_open_admin_secret"
            ),
            new TestCase(
                    "token-robustness",
                    "Malformirani/istekli token ne ruši app",
                    "Otpornost",
                    "Aplikacija mora vratiti 401, a ne 500, za loše JWT-ove.",
                    List.of(
                            "GET /api/notes s krivim tokenom",
                            "GET /api/notes s isteklog tokenom",
                            "GET /api/public/ping s krivim tokenom"
                    ),
                    List.of("Zaštićeni endpointi: 401", "Public endpoint: 200"),
                    "com.example.jwtapp.ApiFlowIntegrationTest",
                    "malformed_or_expired_token_never_crashes_app"
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
