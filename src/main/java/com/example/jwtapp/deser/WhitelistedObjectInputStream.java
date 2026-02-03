package com.example.jwtapp.deser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;

public class WhitelistedObjectInputStream extends ObjectInputStream {

    private final Set<String> whitelist;

    public WhitelistedObjectInputStream(InputStream in, Set<String> whitelist) throws IOException {
        super(in);
        this.whitelist = whitelist;
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();

        if (!whitelist.contains(name) && !name.startsWith("java.lang.")) {
            throw new InvalidClassException("Nedozvoljena klasa: " + name);
        }

        return super.resolveClass(desc);
    }
}
