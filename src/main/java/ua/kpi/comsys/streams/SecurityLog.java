package ua.kpi.comsys.streams;

import java.time.LocalDateTime;

public record SecurityLog(String ipAddress, String severityLevel, String eventDescription, LocalDateTime timestamp) {}
