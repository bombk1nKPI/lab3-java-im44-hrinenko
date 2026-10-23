package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    private static final String CRITICAL = "CRITICAL";

    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        return require(stream, "Stream")
                .filter(Objects::nonNull)
                .filter(log -> CRITICAL.equals(log.severityLevel()))
                .findFirst();
    }

    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        Stream<SecurityLog> logs = require(stream, "Stream");
        LocalDateTime limit = require(deadline, "Deadline");
        return logs
                .filter(Objects::nonNull)
                .takeWhile(log -> isBefore(log, limit))
                .toList();
    }

    public List<SecurityLog> getLogsInWindow(Stream<SecurityLog> stream, LocalDateTime from, LocalDateTime to) {
        Stream<SecurityLog> logs = require(stream, "Stream");
        LocalDateTime start = require(from, "Window start");
        LocalDateTime end = require(to, "Window end");
        if (start.isAfter(end)) {
            throw new IllegalArgumentException("Window start must not be after window end");
        }
        return logs
                .filter(Objects::nonNull)
                .dropWhile(log -> isBefore(log, start))
                .takeWhile(log -> isBefore(log, end))
                .toList();
    }

    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        Stream<SecurityLog> logs = require(stream, "Stream");
        if (maxIpsToReport < 1) {
            throw new IllegalArgumentException("Max IPs to report must be positive");
        }
        return logs
                .gather(new IpBurstGatherer(burstThreshold))
                .limit(maxIpsToReport)
                .toList();
    }

    private static boolean isBefore(SecurityLog log, LocalDateTime moment) {
        return Optional.ofNullable(log.timestamp())
                .map(timestamp -> timestamp.isBefore(moment))
                .orElse(false);
    }

    private static <T> T require(T value, String name) {
        return Optional.ofNullable(value)
                .orElseThrow(() -> new IllegalArgumentException(name + " cannot be null"));
    }
}
