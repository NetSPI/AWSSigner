package com.netspi.awssigner.credentials;

import com.netspi.awssigner.log.LogWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.awssdk.utils.Platform;

public class CommandCredentialFetcher implements CredentialFetcher {

    private final String profileName;
    private final List<String> command;

    public CommandCredentialFetcher(String profileName, String command) {
        List<String> cmd = new ArrayList<>();

        if (Platform.isWindows()) {
            cmd.add("cmd.exe");
            cmd.add("/C");
        } else {
            cmd.add("sh");
            cmd.add("-c");
        }

        String builderCommand = Objects.requireNonNull(command);

        cmd.add(builderCommand);

        this.profileName = profileName;
        this.command = Collections.unmodifiableList(cmd);
    }

    /**
     * Execute the external process to retrieve credentials.
     */
    private String executeCommand() throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);

        ByteArrayOutputStream commandOutput = new ByteArrayOutputStream();

        Process process = processBuilder.start();
        try {
            IoUtils.copy(process.getInputStream(), commandOutput, 64000); //max 64KB output

            process.waitFor();

            if (process.exitValue() != 0) {
                throw new IllegalStateException("Command from profile " + profileName + " returned non-zero exit value: " + process.exitValue());
            }

            return new String(commandOutput.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            process.destroy();
        }
    }

    @Override
    public SigningCredentials getCredentials() throws SignerCredentialException {
        try {
            LogWriter.logDebug("Starting command execution for profile: " + profileName);
            String output = executeCommand();
            LogWriter.logDebug("Completed command execution for profile: " + profileName);
            Optional<SigningCredentials> parsedCreds = CredentialsParser.parseCredentialsFromText(output);
            if (parsedCreds.isPresent()) {
                LogWriter.logInfo("Successfully fetched credentials for profile" + profileName + " using command: " + command);
                return parsedCreds.get();
            } else {
                LogWriter.logDebug("No credentials extracted from the following output: " + output);
                throw new SignerCredentialException("No credentials extracted from command output");
            }
        } catch (InterruptedException | IOException | RuntimeException ex) {
            LogWriter.logError("Error while executing command for profile: " + profileName + " with command: \"" + command + "\" resulting in error: " + ex.getMessage());
            throw new SignerCredentialException(ex);
        }
    }

}
