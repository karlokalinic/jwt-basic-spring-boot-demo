package com.example.jwtapp.deser;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class BadGadget implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private static final AtomicInteger TRIGGER_COUNT = new AtomicInteger(0);
    private static final List<String> EVENTS = Collections.synchronizedList(new ArrayList<>());

    private String message;

    public BadGadget() {}

    public BadGadget(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Serial
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        TRIGGER_COUNT.incrementAndGet();
        EVENTS.add("BadGadget.readObject TRIGGERED @ " + Instant.now() + " | message=" + message);
    }

    public static int getTriggerCount() {
        return TRIGGER_COUNT.get();
    }

    public static List<String> getEventsSnapshot() {
        synchronized (EVENTS) {
            return new ArrayList<>(EVENTS);
        }
    }

    @Override
    public String toString() {
        return "BadGadget{message='" + message + "'}";
    }
}
