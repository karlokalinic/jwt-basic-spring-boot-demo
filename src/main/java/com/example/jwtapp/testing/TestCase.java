package com.example.jwtapp.testing;

import java.util.List;

public record TestCase(
        String id,
        String title,
        String group,
        String description,
        List<String> steps,
        List<String> expected,
        String className,
        String methodName
) {
}
