package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.stream.Stream;

final class SecurityLogs {

    static final LocalDateTime START = LocalDateTime.of(2026, 1, 1, 0, 0);
    static final String INFO = "INFO";
    static final String CRITICAL = "CRITICAL";

    private SecurityLogs() {
    }

    static SecurityLog log(String ip, String severity, LocalDateTime timestamp) {
        return new SecurityLog(ip, severity, severity + " from " + ip, timestamp);
    }

    static SecurityLog info(String ip) {
        return log(ip, INFO, START);
    }

    static Stream<SecurityLog> timeline() {
        return Stream.iterate(0L, second -> second + 1)
                .map(second -> log("10.0.0." + second % 2, INFO, START.plusSeconds(second)));
    }

    static Stream<SecurityLog> criticalEvery(int period) {
        return Stream.iterate(1L, index -> index + 1)
                .map(index -> new SecurityLog(
                        "10.0.0." + index % 2,
                        index % period == 0 ? CRITICAL : INFO,
                        "event-" + index,
                        START.plusSeconds(index)));
    }

    static Stream<SecurityLog> alternatingNoise() {
        return Stream.iterate(0L, index -> index + 1)
                .map(index -> info("10.0.0." + index % 2));
    }

    static Stream<SecurityLog> randomNoise(long seed) {
        Random random = new Random(seed);
        return Stream.generate(() -> info("172.16.0." + random.nextInt(256)));
    }

    static Stream<SecurityLog> periodicBursts(int burstLength) {
        return Stream.iterate(1, attacker -> attacker + 1)
                .flatMap(attacker -> Stream.concat(
                        Stream.generate(() -> info(attackerIp(attacker))).limit(burstLength),
                        Stream.of(info("10.0.0.1"))));
    }

    static String attackerIp(int attacker) {
        return "192.168.0." + attacker;
    }
}
