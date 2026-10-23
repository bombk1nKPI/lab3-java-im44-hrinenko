package ua.kpi.comsys.streams;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static ua.kpi.comsys.streams.SecurityLogs.attackerIp;
import static ua.kpi.comsys.streams.SecurityLogs.info;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Timeout(value = 2, unit = TimeUnit.SECONDS)
class IpBurstGathererTest {

    @ParameterizedTest
    @ValueSource(ints = {0, -5})
    void rejectsNotPositiveThreshold(int threshold) {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new IpBurstGatherer(threshold));
        assertEquals("Burst threshold must be positive", exception.getMessage());
    }

    @Test
    void emitsBurstingIpsFromFiniteStream() {
        List<String> result = Stream.of(
                        info("1.1.1.1"), info("1.1.1.1"),
                        info("2.2.2.2"), info("2.2.2.2"), info("2.2.2.2"),
                        info("1.1.1.1"), info("1.1.1.1"))
                .gather(new IpBurstGatherer(2))
                .toList();

        assertEquals(List.of("1.1.1.1", "2.2.2.2"), result);
    }

    @Test
    void stopsWhenDownstreamRejectsOnInfiniteStream() {
        List<String> result = SecurityLogs.periodicBursts(2)
                .gather(new IpBurstGatherer(2))
                .limit(3)
                .toList();

        assertEquals(List.of(attackerIp(1), attackerIp(2), attackerIp(3)), result);
    }

    @Test
    void stopsOnInfiniteStreamWithFindFirst() {
        String result = Stream.concat(SecurityLogs.alternatingNoise().limit(1000), SecurityLogs.periodicBursts(5))
                .gather(new IpBurstGatherer(5))
                .findFirst()
                .orElse("none");

        assertEquals(attackerIp(1), result);
    }

    @Test
    void keepsSeparateStateForEachStream() {
        IpBurstGatherer gatherer = new IpBurstGatherer(2);

        List<String> first = Stream.of(info("1.1.1.1"), info("1.1.1.1")).gather(gatherer).toList();
        List<String> second = Stream.of(info("1.1.1.1"), info("1.1.1.1")).gather(gatherer).toList();

        assertEquals(List.of("1.1.1.1"), first);
        assertEquals(first, second);
    }
}
