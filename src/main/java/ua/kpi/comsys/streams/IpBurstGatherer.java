package ua.kpi.comsys.streams;

import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Gatherer;

public final class IpBurstGatherer implements Gatherer<SecurityLog, IpBurstGatherer.State, String> {

    private final int burstThreshold;

    public IpBurstGatherer(int burstThreshold) {
        if (burstThreshold < 1) {
            throw new IllegalArgumentException("Burst threshold must be positive");
        }
        this.burstThreshold = burstThreshold;
    }

    @Override
    public Supplier<State> initializer() {
        return State::new;
    }

    @Override
    public Integrator<State, SecurityLog, String> integrator() {
        return Integrator.of((state, log, downstream) -> {
            Optional<String> burstIp = Optional.ofNullable(log)
                    .map(SecurityLog::ipAddress)
                    .map(ip -> state.register(ip, burstThreshold))
                    .orElseGet(state::reset);
            return burstIp
                    .map(downstream::push)
                    .orElseGet(() -> !downstream.isRejecting());
        });
    }

    static final class State {

        private final Set<String> reported = new HashSet<>();
        private String currentIp;
        private int streak;

        private Optional<String> register(String ip, int threshold) {
            if (Objects.equals(ip, currentIp)) {
                streak++;
            } else {
                currentIp = ip;
                streak = 1;
            }
            return Optional.of(ip).filter(value -> streak == threshold && reported.add(value));
        }

        private Optional<String> reset() {
            currentIp = null;
            streak = 0;
            return Optional.empty();
        }
    }
}
