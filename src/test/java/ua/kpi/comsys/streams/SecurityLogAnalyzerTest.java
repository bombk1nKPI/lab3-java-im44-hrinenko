package ua.kpi.comsys.streams;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static ua.kpi.comsys.streams.SecurityLogs.CRITICAL;
import static ua.kpi.comsys.streams.SecurityLogs.INFO;
import static ua.kpi.comsys.streams.SecurityLogs.START;
import static ua.kpi.comsys.streams.SecurityLogs.attackerIp;
import static ua.kpi.comsys.streams.SecurityLogs.info;
import static ua.kpi.comsys.streams.SecurityLogs.log;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Timeout(value = 2, unit = TimeUnit.SECONDS)
class SecurityLogAnalyzerTest {

    private SecurityLogAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SecurityLogAnalyzer();
    }

    @Nested
    class FindFirstCriticalEvent {

        @Test
        void throwsWhenStreamIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.findFirstCriticalEvent(null));
            assertEquals("Stream cannot be null", exception.getMessage());
        }

        @Test
        void findsCriticalEventInInfiniteStream() {
            Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(SecurityLogs.criticalEvery(1000));

            assertEquals(Optional.of("event-1000"), result.map(SecurityLog::eventDescription));
        }

        @Test
        void consumesInfiniteStreamOnlyUntilFirstMatch() {
            AtomicInteger consumed = new AtomicInteger();

            analyzer.findFirstCriticalEvent(SecurityLogs.criticalEvery(50).peek(log -> consumed.incrementAndGet()));

            assertEquals(50, consumed.get());
        }

        @Test
        void returnsFirstElementWhenItIsCritical() {
            SecurityLog critical = log("10.0.0.9", CRITICAL, START);

            Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(
                    Stream.concat(Stream.of(critical), SecurityLogs.criticalEvery(10)));

            assertEquals(Optional.of(critical), result);
        }

        @Test
        void skipsNullElementsBeforeCriticalEvent() {
            SecurityLog critical = log("10.0.0.9", CRITICAL, START);
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(null, info("10.0.0.1"), null, critical),
                    SecurityLogs.alternatingNoise());

            assertEquals(Optional.of(critical), analyzer.findFirstCriticalEvent(stream));
        }

        @Test
        void returnsEmptyWhenFiniteStreamHasNoCriticalEvent() {
            Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(
                    SecurityLogs.alternatingNoise().limit(100));

            assertAll(
                    () -> assertTrue(result.isEmpty()),
                    () -> assertEquals("none", result.map(SecurityLog::ipAddress).orElse("none")));
        }

        @Test
        void returnsEmptyForEmptyStream() {
            assertTrue(analyzer.findFirstCriticalEvent(Stream.empty()).isEmpty());
        }

        @ParameterizedTest
        @ValueSource(strings = {"critical", "Critical", " CRITICAL", "CRITICAL "})
        void matchesSeverityExactly(String severity) {
            SecurityLog critical = log("10.0.0.9", CRITICAL, START);
            Stream<SecurityLog> stream = Stream.of(log("10.0.0.1", severity, START), critical);

            assertEquals(Optional.of(critical), analyzer.findFirstCriticalEvent(stream));
        }

        @Test
        void ignoresEventsWithNullSeverity() {
            SecurityLog critical = log("10.0.0.9", CRITICAL, START);
            Stream<SecurityLog> stream = Stream.of(log("10.0.0.1", null, START), critical);

            assertEquals(Optional.of(critical), analyzer.findFirstCriticalEvent(stream));
        }
    }

    @Nested
    class GetLogsBeforeDeadline {

        @Test
        void throwsWhenStreamIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsBeforeDeadline(null, START));
            assertEquals("Stream cannot be null", exception.getMessage());
        }

        @Test
        void throwsWhenDeadlineIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsBeforeDeadline(SecurityLogs.timeline(), null));
            assertEquals("Deadline cannot be null", exception.getMessage());
        }

        @Test
        void collectsLogsFromInfiniteStreamUntilDeadline() {
            LocalDateTime deadline = START.plusSeconds(10);

            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(SecurityLogs.timeline(), deadline);

            assertAll(
                    () -> assertEquals(10, result.size()),
                    () -> assertEquals(START, result.getFirst().timestamp()),
                    () -> assertEquals(START.plusSeconds(9), result.getLast().timestamp()),
                    () -> assertTrue(result.stream().allMatch(log -> log.timestamp().isBefore(deadline))));
        }

        @Test
        void excludesEventExactlyAtDeadline() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(SecurityLogs.timeline(), START.plusSeconds(1));

            assertEquals(List.of(START), result.stream().map(SecurityLog::timestamp).toList());
        }

        @Test
        void returnsEmptyListWhenDeadlineAlreadyPassed() {
            assertTrue(analyzer.getLogsBeforeDeadline(SecurityLogs.timeline(), START.minusDays(1)).isEmpty());
        }

        @Test
        void stopsConsumingInfiniteStreamAfterDeadline() {
            AtomicInteger consumed = new AtomicInteger();

            analyzer.getLogsBeforeDeadline(
                    SecurityLogs.timeline().peek(log -> consumed.incrementAndGet()), START.plusSeconds(5));

            assertEquals(6, consumed.get());
        }

        @Test
        void skipsNullElements() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(null, log("10.0.0.1", INFO, START.minusSeconds(1)), null),
                    SecurityLogs.timeline());

            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(stream, START.plusSeconds(2));

            assertEquals(3, result.size());
        }

        @Test
        void stopsAtLogWithoutTimestamp() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(log("10.0.0.1", INFO, START), log("10.0.0.2", INFO, null)),
                    SecurityLogs.timeline());

            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(stream, START.plusDays(1));

            assertEquals(List.of("10.0.0.1"), result.stream().map(SecurityLog::ipAddress).toList());
        }
    }

    @Nested
    class GetLogsInWindow {

        @Test
        void throwsWhenStreamIsNull() {
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsInWindow(null, START, START.plusSeconds(1)));
        }

        @Test
        void throwsWhenWindowStartIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsInWindow(SecurityLogs.timeline(), null, START));
            assertEquals("Window start cannot be null", exception.getMessage());
        }

        @Test
        void throwsWhenWindowEndIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsInWindow(SecurityLogs.timeline(), START, null));
            assertEquals("Window end cannot be null", exception.getMessage());
        }

        @Test
        void throwsWhenWindowStartIsAfterEnd() {
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsInWindow(SecurityLogs.timeline(), START.plusSeconds(5), START));
        }

        @Test
        void collectsLogsInsideWindowFromInfiniteStream() {
            List<SecurityLog> result = analyzer.getLogsInWindow(
                    SecurityLogs.timeline(), START.plusSeconds(5), START.plusSeconds(8));

            assertEquals(
                    List.of(START.plusSeconds(5), START.plusSeconds(6), START.plusSeconds(7)),
                    result.stream().map(SecurityLog::timestamp).toList());
        }

        @Test
        void returnsEmptyListForEmptyWindow() {
            LocalDateTime moment = START.plusSeconds(3);

            assertTrue(analyzer.getLogsInWindow(SecurityLogs.timeline(), moment, moment).isEmpty());
        }
    }

    @Nested
    class DetectIpBursts {

        @Test
        void throwsWhenStreamIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.detectIpBursts(null, 3, 1));
            assertEquals("Stream cannot be null", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
        void throwsWhenBurstThresholdIsNotPositive(int threshold) {
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.detectIpBursts(SecurityLogs.periodicBursts(3), threshold, 1));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
        void throwsWhenMaxIpsToReportIsNotPositive(int maxIps) {
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.detectIpBursts(SecurityLogs.periodicBursts(3), 3, maxIps));
        }

        @Test
        void reportsFirstBurstingIpsFromInfiniteStream() {
            List<String> result = analyzer.detectIpBursts(SecurityLogs.periodicBursts(3), 3, 4);

            assertEquals(List.of(attackerIp(1), attackerIp(2), attackerIp(3), attackerIp(4)), result);
        }

        @Test
        void stopsConsumingInfiniteStreamAfterReportLimit() {
            AtomicInteger consumed = new AtomicInteger();

            analyzer.detectIpBursts(SecurityLogs.periodicBursts(3).peek(log -> consumed.incrementAndGet()), 3, 2);

            assertEquals(7, consumed.get());
        }

        @Test
        void ignoresSeriesShorterThanThreshold() {
            Stream<SecurityLog> stream = Stream.concat(
                    SecurityLogs.periodicBursts(2).limit(300),
                    Stream.generate(() -> info("8.8.8.8")));

            assertEquals(List.of("8.8.8.8"), analyzer.detectIpBursts(stream, 3, 1));
        }

        @Test
        void resetsSeriesWhenAnotherIpInterrupts() {
            Stream<SecurityLog> stream = Stream.of(
                    info("1.1.1.1"), info("1.1.1.1"), info("2.2.2.2"), info("1.1.1.1"), info("1.1.1.1"),
                    info("3.3.3.3"), info("3.3.3.3"), info("3.3.3.3"));

            assertEquals(List.of("3.3.3.3"), analyzer.detectIpBursts(stream, 3, 5));
        }

        @Test
        void reportsEachIpOnlyOnce() {
            Stream<SecurityLog> repeatedAttacker = Stream.iterate(0, index -> index + 1)
                    .map(index -> index % 4 == 3 ? info("10.0.0.1") : info("6.6.6.6"));
            Stream<SecurityLog> stream = Stream.concat(repeatedAttacker.limit(400), SecurityLogs.periodicBursts(3));

            assertEquals(List.of("6.6.6.6", attackerIp(1)), analyzer.detectIpBursts(stream, 3, 2));
        }

        @Test
        void reportsIpWhenSeriesContinuesBeyondThreshold() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.generate(() -> info("7.7.7.7")).limit(10),
                    SecurityLogs.periodicBursts(3));

            assertEquals(List.of("7.7.7.7", attackerIp(1)), analyzer.detectIpBursts(stream, 3, 2));
        }

        @Test
        void reportsEveryNewIpWhenThresholdIsOne() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(info("1.1.1.1"), info("1.1.1.1"), info("2.2.2.2"), info("1.1.1.1")),
                    SecurityLogs.randomNoise(42));

            assertEquals(List.of("1.1.1.1", "2.2.2.2"), analyzer.detectIpBursts(stream, 1, 2));
        }

        @Test
        void nullLogBreaksSeries() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(info("1.1.1.1"), info("1.1.1.1"), null, info("1.1.1.1")),
                    SecurityLogs.periodicBursts(3));

            assertEquals(List.of(attackerIp(1)), analyzer.detectIpBursts(stream, 3, 1));
        }

        @Test
        void nullIpBreaksSeries() {
            Stream<SecurityLog> stream = Stream.concat(
                    Stream.of(info("1.1.1.1"), info("1.1.1.1"), info(null), info("1.1.1.1")),
                    SecurityLogs.periodicBursts(3));

            assertEquals(List.of(attackerIp(1)), analyzer.detectIpBursts(stream, 3, 1));
        }

        @Test
        void returnsPartialReportForFiniteStream() {
            List<String> result = analyzer.detectIpBursts(SecurityLogs.periodicBursts(3).limit(8), 3, 10);

            assertEquals(List.of(attackerIp(1), attackerIp(2)), result);
        }

        @Test
        void returnsEmptyListForEmptyStream() {
            assertTrue(analyzer.detectIpBursts(Stream.empty(), 3, 5).isEmpty());
        }
    }
}
