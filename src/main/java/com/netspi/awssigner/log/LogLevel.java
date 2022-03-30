package com.netspi.awssigner.log;

public enum LogLevel {
    ERROR(0), INFO(1), DEBUG(2);
    private final int severity;

    LogLevel(int severity) {
        this.severity = severity;
    }

    public int getSeverity() {
        return severity;
    }

}
