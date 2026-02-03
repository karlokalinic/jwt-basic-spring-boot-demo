# 📖 KOMPLETNA DOKUMENTACIJA: JWT Security Demo Aplikacija

> **Za prezentaciju:** Ovaj dokument objašnjava SVE što aplikacija radi, datoteku po datoteku, kao da ti pričam dok pijemo kavu ☕

---

## 🎯 ŠTO JE OVA APLIKACIJA?

Ovo je **demo sigurnosna aplikacija** koja pokazuje:
1. **JWT (JSON Web Token) autentifikaciju** - kako se korisnik logira i dobiva "propusnicu"
2. **SQL Injection ranjivost** - kako hakeri mogu ukrasti podatke
3. **Deserijalizacija napadi** - kako hakeri mogu izvršiti kod na serveru
4. **JUnit testovi** - automatsko testiranje sigurnosti

**Ukratko:** To je "laboratorij" za učenje web sigurnosti!

---

## 🏗️ ARHITEKTURA PROJEKTA

```
jwt-basic-spring-boot-demo/
│
├── src/main/java/com/example/jwtapp/
│   ├── JwtAppApplication.java     ← Ulazna točka (main)
│   ├── auth/                       ← Login sustav
│   ├── jwt/                        ← JWT token logika
│   ├── config/                     ← Sigurnosne postavke
│   ├── api/                        ← SQL Injection demo
│   ├── deser/                      ← Deserijalizacija demo
│   └── testing/                    ← JUnit test runner
│
├── src/main/resources/
│   ├── application.properties     ← Konfiguracija
│   ├── schema.sql                 ← Kreiranje tablica
│   ├── data.sql                   ← Testni podaci
│   └── static/index.html          ← Web sučelje
│
└── pom.xml                        ← Maven dependencies
```

---

## 🔐 POGLAVLJE 1: JWT AUTENTIFIKACIJA

### Što je JWT?

JWT (JSON Web Token) je **digitalna propusnica**. Kad se ulogiraš:
1. Server provjeri korisničko ime i lozinku
2. Ako je OK, server generira JWT token
3. Ti šalješ taj token uz svaki zahtjev
4. Server verificira token i zna tko si

**Analogija:** JWT je kao narukvica na festivalu 🎪 - jednom dobiješ, pokazuješ svugdje

### Kako izgleda JWT?

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJzdHVkZW50IiwiaXNzIjoic2VjdXJlLWFwaSIsInJvbCI6WyJVU0VSIl19.
pQx3Xn5KoZ8YrN...
```

To je **3 dijela odvojena točkama**:
1. **Header** - algoritam (HS256) i tip (JWT)
2. **Payload** - podaci (username, roles, expiry)
3. **Signature** - digitalni potpis koji sprječava falsificiranje

### Relevantne datoteke:

#### 📄 `JwtService.java` — Srce JWT sustava

```java
@Service
public class JwtService {
    // Ova metoda GENERIRA token nakon uspješnog logina
    public String generateToken(UserDetails user) {
        return Jwts.builder()
            .setSubject(user.getUsername())      // Tko je korisnik
            .claim("rol", roles)                 // Koje ima uloge (USER, ADMIN)
            .setIssuedAt(now)                    // Kada je izdan
            .setExpiration(exp)                  // Kada istječe (15 min)
            .signWith(signingKey, HS256)         // Potpisano tajnim ključem
            .compact();
    }
    
    // Ova metoda VALIDIRA token iz zahtjeva
    public boolean isTokenValid(String token, UserDetails user) {
        return username.equals(user.getUsername()) && !isExpired(token);
    }
}
```

**Jednostavno rečeno:** `JwtService` je kao **pisarnica koja izdaje i provjerava propusnice**.

---

#### 📄 `JwtAuthenticationFilter.java` — Čuvar na vratima

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    protected void doFilterInternal(...) {
        // 1. Uzmi Authorization header
        String authHeader = request.getHeader("Authorization");
        
        // 2. Ako počinje s "Bearer ", izvadi token
        String token = authHeader.substring(7);
        
        // 3. Izvadi username iz tokena
        String username = jwtService.extractUsername(token);
        
        // 4. Ako je token validan, postavi SecurityContext
        if (jwtService.isTokenValid(token, userDetails)) {
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
    }
}
```

**Jednostavno rečeno:** Ovaj filter je kao **zaštitar** koji provjerava svačiju narukvicu prije ulaska.

---

#### 📄 `AuthController.java` — Login endpoint

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        // 1. Provjeri username + password
        Authentication auth = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );
        
        // 2. Generiraj JWT token
        String token = jwtService.generateToken(user);
        
        // 3. Vrati token korisniku
        return ResponseEntity.ok(new LoginResponse(token));
    }
}
```

**Jednostavno rečeno:** Ovo je **recepcija** gdje daješ osobnu i dobiješ narukvicu.

---

#### 📄 `SecurityConfig.java` — Tko smije što

```java
@Configuration
public class SecurityConfig {
    
    // Korisnici u memoriji (za demo)
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails student = User.withUsername("student")
            .password(encoder.encode("pass123"))
            .roles("USER")
            .build();
            
        UserDetails admin = User.withUsername("admin")
            .password(encoder.encode("admin123"))
            .roles("ADMIN", "USER")   // Admin ima obje uloge!
            .build();
    }
    
    // Pravila pristupa
    @Bean
    public SecurityFilterChain securityFilterChain(...) {
        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()     // Login = javno
                .requestMatchers("/api/tests/**").hasRole("USER") // Testovi = samo ulogirani
                .requestMatchers("/api/admin/**").hasRole("ADMIN") // Admin = samo admini
            );
    }
}
```

**Jednostavno rečeno:** Ovo je **lista pravila** - tko smije ući gdje, kao VIP lista na ulazu.

---

## 💉 POGLAVLJE 2: SQL INJECTION DEMO

### Što je SQL Injection?

SQL Injection je napad gdje haker **ubacuje SQL kod** u input polje i dobiva pristup podacima koje ne bi smio vidjeti.

**Primjer:**  
Umjesto username-a `student`, uneseš: `' OR '1'='1`

To pretvara SQL upit iz:
```sql
SELECT * FROM users WHERE username = 'student'
```
U:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1'
```

A `'1'='1'` je **uvijek true**, pa vrati SVE korisnike! 🚨

### Relevantne datoteke:

#### 📄 `SqlInjectionController.java` — Ranjivi i sigurni endpoint

```java
@RestController
@RequestMapping("/api/sql")
public class SqlInjectionController {
    
    // ⚠️ RANJIVO - NE KORISTI OVO U PRODUKCIJI!
    @GetMapping("/vuln")
    public List<Map<String, Object>> vulnerableLookup(@RequestParam String username) {
        // Direktno spajanje stringa = OPASNO!
        String sql = "SELECT * FROM demo_users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }
    
    // ✅ SIGURNO - Koristi prepared statements
    @GetMapping("/safe")
    public List<Map<String, Object>> safeLookup(@RequestParam String username) {
        // Parametrizirani upit = SIGURNO
        String sql = "SELECT * FROM demo_users WHERE username = ?";
        return jdbcTemplate.queryForList(sql, username);  // username ide kao parametar
    }
}
```

**Jednostavno rečeno:**  
- **Ranjivi endpoint** je kao da netko može **prepisati tvoj upit**
- **Sigurni endpoint** tretira input kao **čisti tekst**, ne kao SQL kod

#### 📄 `schema.sql` i `data.sql` — Demo baza

```sql
-- schema.sql - Kreira tablicu
CREATE TABLE demo_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(64),
  role VARCHAR(32)
);

-- data.sql - Ubacuje testne podatke
INSERT INTO demo_users (username, role) VALUES
  ('student', 'USER'),
  ('admin', 'ADMIN'),
  ('assistant', 'USER');
```

---

## 🧪 POGLAVLJE 3: DESERIJALIZACIJA DEMO

### Što je nesigurna deserijalizacija?

Kada program prima **serijalizirane objekte** (npr. Base64 string) i pretvara ih nazad u Java objekte, haker može poslati **zlonamjerni objekt** koji izvršava kod!

**Analogija:** Kao da netko pošalje paket koji izgleda kao poklon 🎁, ali kad ga otvoriš - BOOM 💥

### Relevantne datoteke:

#### 📄 `DeserializationController.java`

```java
@RestController
@RequestMapping("/api/deser")
public class DeserializationController {
    
    // Deserijalizira payload - OPASNO ako nema zaštite!
    @PostMapping("/unsafe")
    public DeserResponse unsafeDeserialize(@RequestBody DeserRequest req) {
        // Prima Base64 string i pretvara u Java objekt
        return service.deserializeUnsafe(req.payloadBase64());
    }
    
    // Sigurna verzija s whitelistom klasa
    @PostMapping("/safe")
    public DeserResponse safeDeserialize(@RequestBody DeserRequest req) {
        // Provjerava potpis i dozvoljava samo određene klase
        return service.deserializeSafe(req.payloadBase64(), req.sigBase64());
    }
}
```

#### 📄 `BadGadget.java` — Simulirani "exploit"

```java
public class BadGadget implements Serializable {
    // Ova metoda se poziva automatski pri deserijalizaciji!
    private void readObject(ObjectInputStream in) {
        System.out.println("🚨 GADGET TRIGGERED! Hakiran si!");
        // U stvarnosti bi ovdje bila zlonamjerna akcija
    }
}
```

**Jednostavno rečeno:** `BadGadget` simulira kako haker može izvršiti kod samo slanjem serijaliziranog objekta.

---

## 🧪 POGLAVLJE 4: JUNIT TESTOVI

### Što su JUnit testovi?

JUnit je framework za **automatsko testiranje**. Umjesto ručnog klikanja, napišeš kod koji testira kod.

### Relevantne datoteke:

#### 📄 `TestExecutionController.java` — Pokreće testove iz UI-a

```java
@RestController
@RequestMapping("/api/tests")
public class TestExecutionController {
    
    @PostMapping("/run")
    public TestRunSummary runTests(@RequestBody TestRunRequest request) {
        // Koristi JUnit Platform Launcher API
        Launcher launcher = LauncherFactory.create();
        launcher.execute(request);
        // Vraća rezultate: passed, failed, duration...
    }
    
    @GetMapping("/catalog")
    public List<TestCaseView> getCatalog() {
        // Vraća popis dostupnih testova
    }
}
```

#### 📄 `AuthFlowTest.java` — Testira JWT autentifikaciju

```java
public class AuthFlowTest {
    
    @Test
    void login_withValidCredentials_returnsToken() {
        // Simulira login i provjerava da dobije token
    }
    
    @Test
    void protectedEndpoint_withoutToken_returns401() {
        // Provjerava da zaštićeni endpoint odbije bez tokena
    }
}
```

#### 📄 `SqlInjectionTest.java` — Testira SQL ranjivost

```java
public class SqlInjectionTest {
    
    @Test
    void vulnEndpoint_withInjection_returnsAllUsers() {
        // Šalje SQL injection i očekuje da dobije sve korisnike
    }
    
    @Test
    void safeEndpoint_withInjection_returns0Users() {
        // Šalje SQL injection i očekuje 0 rezultata (sigurno!)
    }
}
```

---

## ⚙️ POGLAVLJE 5: KONFIGURACIJA

#### 📄 `application.properties`

```properties
# Server
server.port=8080

# Baza podataka (H2 in-memory)
spring.datasource.url=jdbc:h2:mem:jwt_demo

# JWT postavke
app.jwt.secret=change-me-change-me-change-me-change-me!  # TAJNI KLJUČ za potpis
app.jwt.expMinutes=15                                     # Token vrijedi 15 min
app.jwt.issuer=secure-api                                 # Tko izdaje token
app.jwt.audience=secure-app                               # Za koga je token
```

**VAŽNO:** U produkciji, `app.jwt.secret` NIKAD ne smije biti u kodu! Koristi environment varijable.

#### 📄 `pom.xml` — Dependencies

Glavne biblioteke:
- `spring-boot-starter-web` — Web server
- `spring-boot-starter-security` — Spring Security
- `jjwt-api`, `jjwt-impl`, `jjwt-jackson` — JWT biblioteka
- `h2` — In-memory baza
- `junit-platform-launcher` — Za pokretanje testova iz API-a

---

## 🖥️ POGLAVLJE 6: FRONTEND (index.html)

Frontend je **jedna HTML stranica** sa JavaScript-om koja komunicira s backendom.

### Glavne funkcije:

```javascript
// LOGIN - šalje username/password, sprema token
async function login() {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
    token = response.token;
    localStorage.setItem('jwt_token', token);
}

// API POZIV - dodaje Bearer token u header
async function api(method, url) {
    return fetch(url, {
        headers: {
            'Authorization': `Bearer ${token}`  // Token ide ovdje!
        }
    });
}

// SQL INJECTION TEST
async function sqlVuln() {
    await api('GET', '/api/sql/vuln?username=' + inputValue);
}
```

---

## 🚀 POGLAVLJE 7: DEPLOYMENT

#### 📄 `Dockerfile`

```dockerfile
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17 AS build
COPY . .
RUN mvn clean package -DskipTests

# Stage 2: Run
FROM eclipse-temurin:17-jre
COPY --from=build /target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Što ovo radi:**
1. Uzima Maven image, gradi JAR
2. Uzima lagani JRE image, pokreće JAR
3. Rezultat: optimizirana Docker slika

#### 📄 `render.yaml` — Render.com deployment

```yaml
services:
  - type: web
    name: jwt-security-demo
    runtime: docker
    plan: free
```

---

## 📋 SAŽETAK ZA PREZENTACIJU

| Komponenta | Što radi | Datoteka |
|------------|----------|----------|
| **JWT generiranje** | Kreira token s username, roles, expiry | `JwtService.java` |
| **JWT validacija** | Provjerava token na svakom zahtjevu | `JwtAuthenticationFilter.java` |
| **Login** | Prima credentials, vraća token | `AuthController.java` |
| **Autorizacija** | Definira tko smije pristupiti čemu | `SecurityConfig.java` |
| **SQL Injection** | Pokazuje ranjivu vs. sigurnu verziju | `SqlInjectionController.java` |
| **Deserijalizacija** | Demo napada preko serijaliziranih objekata | `DeserializationController.java` |
| **Testovi** | Automatski testira sigurnost | `AuthFlowTest.java`, `SqlInjectionTest.java` |
| **Frontend** | Web sučelje za interakciju | `index.html` |

---

## ❓ FAQ - Pitanja koja bi ti mogli postaviti

**Q: Zašto koristimo JWT umjesto session cookies?**  
A: JWT je **stateless** - server ne mora pamtiti sesije, samo provjerava potpis. Skalabilnije je za distribuirane sustave.

**Q: Kako JWT sprječava falsificiranje?**  
A: Signature dio tokena je **HMAC hash** cijelog tokena + tajnog ključa. Bez ključa ne možeš napraviti validan potpis.

**Q: Zašto je prepared statement siguran od SQL injection?**  
A: Jer **odvaja SQL kod od podataka**. Input se tretira kao string, nikad kao SQL.

**Q: Kako se zaštititi od nesigurne deserijalizacije?**  
A: Whitelist dozvoljenih klasa, potpisi, ili izbjegavati Java serialization potpuno (koristiti JSON).

---

## 🔧 KAKO POKRENUTI

```bash
# 1. Build i pokretanje
mvn clean spring-boot:run

# 2. Otvori browser
http://localhost:8080

# 3. Login podaci
student / pass123   (obični korisnik)
admin / admin123    (administrator)
```

---

**Autor:** Generirana dokumentacija za Security Lab prezentaciju  
**Stack:** Spring Boot 3.3.2, Java 17, JWT (JJWT), H2 Database, JUnit 5
