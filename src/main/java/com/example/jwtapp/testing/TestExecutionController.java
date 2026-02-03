package com.example.jwtapp.testing;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.TestSource;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/tests")
public class TestExecutionController {

    public record TestCaseView(
            String id,
            String title,
            String group,
            String description,
            List<String> steps,
            List<String> expected
    ) {}

    public record TestRunRequest(List<String> testIds) {}

    public record TestResult(
            String id,
            String title,
            String group,
            String status,
            long durationMs,
            String failureMessage,
            String failureTrace
    ) {}

    public record TestRunSummary(
            int total,
            int passed,
            int failed,
            int aborted,
            int skipped,
            long durationMs,
            List<TestResult> results
    ) {}

    @GetMapping("/catalog")
    public List<TestCaseView> catalog() {
        return TestCatalog.cases().stream()
                .map(test -> new TestCaseView(
                        test.id(),
                        test.title(),
                        test.group(),
                        test.description(),
                        test.steps(),
                        test.expected()
                ))
                .toList();
    }

    @PostMapping("/run")
    public TestRunSummary runTests(@RequestBody(required = false) TestRunRequest request) {
        List<String> requested = request == null ? List.of() : Optional.ofNullable(request.testIds()).orElse(List.of());
        List<TestCase> selected = requested.isEmpty()
                ? TestCatalog.cases()
                : requested.stream().map(this::resolveTestCase).toList();

        if (selected.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nema odabranih testova.");
        }

        List<Object> selectorList = selected.stream().map(this::toSelector).toList();
        @SuppressWarnings("unchecked,rawtypes")
        LauncherDiscoveryRequest discoveryRequest = LauncherDiscoveryRequestBuilder.request()
                .selectors((List) selectorList)
                .build();

        LauncherConfig config = LauncherConfig.builder().enableTestEngineAutoRegistration(true).build();
        Launcher launcher = LauncherFactory.create(config);

        CollectingListener listener = new CollectingListener(selected);
        SummaryGeneratingListener summaryListener = new SummaryGeneratingListener();
        launcher.registerTestExecutionListeners(listener, summaryListener);
        launcher.execute(discoveryRequest);

        return listener.toSummary();
    }

    private TestCase resolveTestCase(String id) {
        TestCase found = TestCatalog.byId(id);
        if (found == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nepoznat test id: " + id);
        }
        return found;
    }

    private Object toSelector(TestCase testCase) {
        try {
            Class<?> clazz = Class.forName(testCase.className());
            return selectMethod(clazz, testCase.methodName());
        } catch (ClassNotFoundException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Test class nije pronađen: " + testCase.className(), ex);
        }
    }

    private static class CollectingListener implements TestExecutionListener {
        private final Map<String, TestCase> casesByMethod;
        private final List<TestResult> results = new CopyOnWriteArrayList<>();
        private final Map<TestIdentifier, Instant> startTimes = new ConcurrentHashMap<>();
        private Instant suiteStart;
        private Instant suiteEnd;

        private CollectingListener(List<TestCase> cases) {
            casesByMethod = cases.stream().collect(Collectors.toMap(
                    testCase -> testCase.className() + "#" + testCase.methodName(),
                    testCase -> testCase
            ));
        }

        @Override
        public void testPlanExecutionStarted(org.junit.platform.launcher.TestPlan testPlan) {
            suiteStart = Instant.now();
        }

        @Override
        public void testPlanExecutionFinished(org.junit.platform.launcher.TestPlan testPlan) {
            suiteEnd = Instant.now();
        }

        @Override
        public void executionStarted(TestIdentifier testIdentifier) {
            if (testIdentifier.isTest()) {
                startTimes.put(testIdentifier, Instant.now());
            }
        }

        @Override
        public void executionSkipped(TestIdentifier testIdentifier, String reason) {
            if (testIdentifier.isTest()) {
                TestCase resolved = resolveCase(testIdentifier);
                results.add(new TestResult(
                        resolved.id(),
                        resolved.title(),
                        resolved.group(),
                        "SKIPPED",
                        0L,
                        reason,
                        null
                ));
            }
        }

        @Override
        public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
            if (!testIdentifier.isTest()) {
                return;
            }

            TestCase resolved = resolveCase(testIdentifier);
            Instant started = startTimes.getOrDefault(testIdentifier, Instant.now());
            long durationMs = Duration.between(started, Instant.now()).toMillis();
            String failureMessage = null;
            String failureTrace = null;

            if (testExecutionResult.getStatus() == TestExecutionResult.Status.FAILED) {
                Throwable throwable = testExecutionResult.getThrowable().orElse(null);
                if (throwable != null) {
                    failureMessage = throwable.getMessage();
                    StringWriter sw = new StringWriter();
                    throwable.printStackTrace(new PrintWriter(sw));
                    failureTrace = sw.toString();
                }
            }

            results.add(new TestResult(
                    resolved.id(),
                    resolved.title(),
                    resolved.group(),
                    testExecutionResult.getStatus().name(),
                    durationMs,
                    failureMessage,
                    failureTrace
            ));
        }

        private TestCase resolveCase(TestIdentifier testIdentifier) {
            Optional<TestSource> source = testIdentifier.getSource();
            if (source.isPresent() && source.get() instanceof MethodSource methodSource) {
                String key = methodSource.getClassName() + "#" + methodSource.getMethodName();
                TestCase resolved = casesByMethod.get(key);
                if (resolved != null) {
                    return resolved;
                }
            }

            return new TestCase(
                    testIdentifier.getUniqueId(),
                    testIdentifier.getDisplayName(),
                    "Nepoznato",
                    "Nema mapiranja u katalogu.",
                    List.of(),
                    List.of(),
                    "",
                    ""
            );
        }

        private TestRunSummary toSummary() {
            int passed = countStatus("SUCCESSFUL");
            int failed = countStatus("FAILED");
            int aborted = countStatus("ABORTED");
            int skipped = countStatus("SKIPPED");
            int total = results.size();
            long durationMs = suiteStart != null && suiteEnd != null
                    ? Duration.between(suiteStart, suiteEnd).toMillis()
                    : 0L;

            return new TestRunSummary(
                    total,
                    passed,
                    failed,
                    aborted,
                    skipped,
                    durationMs,
                    results
            );
        }

        private int countStatus(String status) {
            return (int) results.stream().filter(result -> status.equals(result.status())).count();
        }
    }
}
