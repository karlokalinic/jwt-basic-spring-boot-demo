package com.example.jwtapp.deser;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/deser")
public class DeserializationController {

    private final DeserializationService service;
    private final boolean enabled;

    public DeserializationController(
            DeserializationService service,
            @Value("${app.securitylabs.deser.enabled:true}") boolean enabled
    ) {
        this.service = service;
        this.enabled = enabled;
    }

    public record DeserRequest(String payloadBase64, String sigBase64) {}
    public record DeserSample(String name, String payloadBase64, String sigBase64) {}
    public record SerializeRequest(String username, String role, String password, String createdAt) {}
    public record SerializeResponse(
            String payloadBase64,
            String sigBase64,
            String serializedClass,
            String serializedSummary,
            String note
    ) {}
    public record DeserResponse(
            boolean ok,
            String mode,
            String deserializedClass,
            String deserializedSummary,
            int badGadgetTriggerCount,
            List<String> badGadgetEvents
    ) {}

    @GetMapping("/samples")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<DeserSample>> samples() {
        ensureEnabled();

        DeserializationService.Envelope good = service.makeSampleGood();
        DeserializationService.Envelope bad = service.makeSampleBad();

        return ResponseEntity.ok(List.of(
                new DeserSample("GOOD_DemoUser", good.payloadBase64(), good.sigBase64()),
                new DeserSample("BAD_BadGadget", bad.payloadBase64(), bad.sigBase64())
        ));
    }

    @PostMapping("/serialize")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<SerializeResponse> serialize(@RequestBody SerializeRequest req) {
        ensureEnabled();

        String username = sanitizeRequired(req.username(), "username");
        String role = sanitizeRequired(req.role(), "role");
        String createdAt = req.createdAt() == null || req.createdAt().isBlank()
                ? java.time.Instant.now().toString()
                : req.createdAt().trim();

        DemoUser user = new DemoUser(
                username,
                role,
                req.password(),
                createdAt
        );

        DeserializationService.Envelope envelope = service.serializeAndSign(user);

        return ResponseEntity.ok(new SerializeResponse(
                envelope.payloadBase64(),
                envelope.sigBase64(),
                user.getClass().getName(),
                user.toString(),
                "password je transient → ne ulazi u serialized payload."
        ));
    }

    @PostMapping("/vuln")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<DeserResponse> vuln(@RequestBody DeserRequest req) {
        ensureEnabled();

        Object obj = service.deserializeVulnSandboxed(req.payloadBase64());

        return ResponseEntity.ok(new DeserResponse(
                true,
                "vuln-sandbox",
                obj.getClass().getName(),
                String.valueOf(obj),
                BadGadget.getTriggerCount(),
                BadGadget.getEventsSnapshot()
        ));
    }

    @PostMapping("/safe")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<DeserResponse> safe(@RequestBody DeserRequest req) {
        ensureEnabled();

        Object obj = service.deserializeSafe(req.payloadBase64(), req.sigBase64());

        return ResponseEntity.ok(new DeserResponse(
                true,
                "safe",
                obj.getClass().getName(),
                String.valueOf(obj),
                BadGadget.getTriggerCount(),
                BadGadget.getEventsSnapshot()
        ));
    }

    @GetMapping("/status")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of(
                "enabled", enabled,
                "badGadgetTriggerCount", BadGadget.getTriggerCount()
        ));
    }

    private void ensureEnabled() {
        if (!enabled) {
            throw new InsecureDeserializationException("Deserialization lab je isključen (app.securitylabs.deser.enabled=false).");
        }
    }

    private String sanitizeRequired(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new InsecureDeserializationException("Nedostaje obavezno polje: " + field);
        }
        return value.trim();
    }
}
