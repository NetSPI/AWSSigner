package com.netspi.awssigner.model;

import com.netspi.awssigner.credentials.CommandCredentialFetcher;
import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;
import java.util.Optional;

public class CommandProfile extends AbstractCachingProfile {

    private String command;

    public CommandProfile(String name) {
        super(name);
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getCommand() {
        return Optional.ofNullable(command);
    }

    public void setCommand(String command) {
        if (command != null && command.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.command = null;
        } else {
            this.command = command;
        }
        clearCache();
    }

    @Override
    public boolean requiredFieldsAreSet() {
        return command != null;
    }

    @Override
    protected SigningCredentials getCredentialsNoCache() throws SignerCredentialException {
        if (command == null) {
            throw new SignerCredentialException("Command is not set for profile: " + getName());
        }

        return new CommandCredentialFetcher(name, command).getCredentials();
    }

}
