package com.netspi.awssigner.log;

import burp.BurpExtender;
import java.io.OutputStream;
import java.io.PrintWriter;

/*
 * This isn't good OOP, but it's good enough for this use case. We don't need to
 * pass around an instance to each object which gets messy.
 */
public class LogWriter {

    private PrintWriter out = new PrintWriter(System.out, true);
    private PrintWriter err = new PrintWriter(System.err, true);
    private LogLevel logLevel = LogLevel.ERROR;

    private static final LogWriter logWriter = new LogWriter();

    private LogWriter() {
    }

    public synchronized static void configure(OutputStream outStream, OutputStream errStream) {
        logWriter.out = new PrintWriter(outStream, true);
        logWriter.out.println(BurpExtender.EXTENSION_NAME + " Logging Initialized");
        logWriter.err = new PrintWriter(errStream, true);
    }

    public synchronized static void setLevel(LogLevel level) {
        logWriter.logLevel = level;
    }

    public static LogLevel getLevel() {
        return logWriter.logLevel;
    }

    public static void logDebug(final String message) {
        if (logWriter.logLevel.getSeverity() >= LogLevel.DEBUG.getSeverity()) {
            logWriter.out.println("[DEBUG] " + message);
        }
    }

    public static void logInfo(final String message) {
        if (logWriter.logLevel.getSeverity() >= LogLevel.INFO.getSeverity()) {
            logWriter.out.println("[INFO] " + message);
        }
    }

    public static void logError(final String message) {
        logWriter.err.println("[ERROR] " + message);
    }

}
