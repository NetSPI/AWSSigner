package com.netspi.awssigner.credentials;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CredentialsParser {

    private static final Pattern ACCESS_KEY_PATTERN = Pattern.compile("(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])");
    private static final Pattern SECRET_KEY_PATTERN = Pattern.compile("(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])");
    private static final Pattern SESSION_TOKEN_PATTERN = Pattern.compile("(?<![A-Za-z0-9/+])(?:[A-Za-z0-9+/]){40,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9/+=])");

    /**
     * Attempt to extract static credentials from the input text.
     *
     * @param textToBeParsed
     * @return
     */
    public static Optional<SigningCredentials> parseCredentialsFromText(String textToBeParsed) {
        Matcher accessKeyMatcher = ACCESS_KEY_PATTERN.matcher(textToBeParsed);
        Matcher secretKeyMatcher = SECRET_KEY_PATTERN.matcher(textToBeParsed);
        if (accessKeyMatcher.find() && secretKeyMatcher.find()) {
            String accessKey = accessKeyMatcher.group();
            String secretKey = secretKeyMatcher.group();
            String sessionToken = null;

            Matcher sessionTokenMatcher = SESSION_TOKEN_PATTERN.matcher(textToBeParsed);
            if (sessionTokenMatcher.find()) {
                sessionToken = sessionTokenMatcher.group();
            }

            return Optional.of(new SigningCredentials(accessKey, secretKey, sessionToken));
        }
        return Optional.empty();
    }

}
