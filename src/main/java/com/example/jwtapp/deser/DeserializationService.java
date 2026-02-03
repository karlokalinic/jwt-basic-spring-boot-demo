package com.example.jwtapp.deser;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@Service
public class DeserializationService {

    private static final int MAX_PAYLOAD_BYTES = 16 * 1024;

    private final String hmacSecret;

    public DeserializationService(@Value("${app.securitylabs.deser.hmacSecret:change-me}") String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public record Envelope(String payloadBase64, String sigBase64) {}

    public Envelope makeSampleGood() {
        DemoUser user = new DemoUser("student", "ROLE_USER", "super-secret-password", Instant.now().toString());
        return serializeAndSign(user);
    }

    public Envelope makeSampleBad() {
        BadGadget gadget = new BadGadget("👀 ovo samo logira event pri deserijalizaciji");
        return serializeAndSign(gadget);
    }

    public Object deserializeVulnSandboxed(String payloadBase64) {
        byte[] data = decodeAndValidateSize(payloadBase64);

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            ois.setObjectInputFilter(info -> {
                if (info.streamBytes() > MAX_PAYLOAD_BYTES) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }
                if (info.depth() > 10) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }
                if (info.references() > 10_000) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }

                Class<?> serialClass = info.serialClass();
                if (serialClass == null) {
                    return java.io.ObjectInputFilter.Status.UNDECIDED;
                }

                String name = serialClass.getName();
                if (name.startsWith("com.example.jwtapp.deser.")) {
                    return java.io.ObjectInputFilter.Status.ALLOWED;
                }
                if (name.startsWith("java.lang.") || name.startsWith("java.util.")) {
                    return java.io.ObjectInputFilter.Status.ALLOWED;
                }

                return java.io.ObjectInputFilter.Status.REJECTED;
            });

            return ois.readObject();
        } catch (Exception e) {
            throw new InsecureDeserializationException("Vuln deserijalizacija (sandbox) nije uspjela: " + e.getMessage(), e);
        }
    }

    public Object deserializeSafe(String payloadBase64, String sigBase64) {
        byte[] data = decodeAndValidateSize(payloadBase64);

        String expectedSig = hmacBase64(data);
        if (sigBase64 == null || !constantTimeEquals(expectedSig, sigBase64)) {
            throw new InsecureDeserializationException("Neispravan potpis (HMAC). Payload je odbijen.");
        }

        Set<String> whitelist = Set.of(
                DemoUser.class.getName(),
                "java.lang.String",
                "java.lang.Integer",
                "java.lang.Long",
                "java.util.ArrayList",
                "java.util.LinkedList"
        );

        try (WhitelistedObjectInputStream wois = new WhitelistedObjectInputStream(new ByteArrayInputStream(data), whitelist)) {
            wois.setObjectInputFilter(info -> {
                if (info.streamBytes() > MAX_PAYLOAD_BYTES) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }
                if (info.depth() > 5) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }
                if (info.references() > 1_000) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }

                Class<?> serialClass = info.serialClass();
                if (serialClass == null) {
                    return java.io.ObjectInputFilter.Status.UNDECIDED;
                }

                String name = serialClass.getName();
                if (whitelist.contains(name) || name.startsWith("java.lang.")) {
                    return java.io.ObjectInputFilter.Status.ALLOWED;
                }
                return java.io.ObjectInputFilter.Status.REJECTED;
            });

            Object obj = wois.readObject();
            if (!(obj instanceof DemoUser)) {
                throw new InsecureDeserializationException("Safe endpoint očekuje DemoUser. Dobio: " + obj.getClass().getName());
            }
            return obj;
        } catch (Exception e) {
            throw new InsecureDeserializationException("Safe deserijalizacija nije uspjela: " + e.getMessage(), e);
        }
    }

    public Envelope serializeAndSign(Serializable obj) {
        byte[] bytes = serialize(obj);
        return new Envelope(
                Base64.getEncoder().encodeToString(bytes),
                hmacBase64(bytes)
        );
    }

    private byte[] serialize(Serializable obj) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
            oos.flush();
            return bos.toByteArray();
        } catch (Exception e) {
            throw new InsecureDeserializationException("Serijalizacija nije uspjela: " + e.getMessage(), e);
        }
    }

    private byte[] decodeAndValidateSize(String payloadBase64) {
        if (payloadBase64 == null || payloadBase64.isBlank()) {
            throw new InsecureDeserializationException("payloadBase64 je prazan.");
        }
        byte[] data;
        try {
            data = Base64.getDecoder().decode(payloadBase64);
        } catch (IllegalArgumentException e) {
            throw new InsecureDeserializationException("payloadBase64 nije validan Base64.");
        }
        if (data.length > MAX_PAYLOAD_BYTES) {
            throw new InsecureDeserializationException("Payload prevelik (" + data.length + "B). Odbijeno radi DoS zaštite.");
        }
        return data;
    }

    private String hmacBase64(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(key);
            return Base64.getEncoder().encodeToString(mac.doFinal(data));
        } catch (Exception e) {
            throw new InsecureDeserializationException("HMAC greška: " + e.getMessage(), e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        byte[] aa = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        int diff = aa.length ^ bb.length;
        for (int i = 0; i < Math.min(aa.length, bb.length); i++) {
            diff |= aa[i] ^ bb[i];
        }
        return diff == 0;
    }
}
