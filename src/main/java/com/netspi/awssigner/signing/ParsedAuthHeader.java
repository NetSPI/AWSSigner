package com.netspi.awssigner.signing;

import com.netspi.awssigner.log.LogWriter;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParsedAuthHeader {

    private static final String AUTH_HEADER_PATTERN_ALGORITHM_GROUP = "algorithm";
    private static final String AUTH_HEADER_PATTERN_ACCESS_KEY_GROUP = "accessKeyId";
    private static final String AUTH_HEADER_PATTERN_DATE_GROUP = "date";
    private static final String AUTH_HEADER_PATTERN_REGION_GROUP = "region";
    private static final String AUTH_HEADER_PATTERN_SERVICE_GROUP = "service";
    private static final String AUTH_HEADER_PATTERN_SIGNED_HEADERS_GROUP = "signedheaders";
    private static final String AUTH_HEADER_PATTERN_SIGNATURE_GROUP = "signature";
    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile("Authorization:\\s*(?<" + AUTH_HEADER_PATTERN_ALGORITHM_GROUP + ">AWS4-(?:HMAC|ECDSA-P256)-SHA256)\\s*Credential=(?<" + AUTH_HEADER_PATTERN_ACCESS_KEY_GROUP + ">[\\w-]{1,128})\\/(?<" + AUTH_HEADER_PATTERN_DATE_GROUP + ">\\d{8})\\/(?:(?<" + AUTH_HEADER_PATTERN_REGION_GROUP + ">[\\w-]{0,64})\\/)?(?<" + AUTH_HEADER_PATTERN_SERVICE_GROUP + ">\\S{0,128})\\/aws4_request,?\\s+SignedHeaders=(?<" + AUTH_HEADER_PATTERN_SIGNED_HEADERS_GROUP + ">\\S+),?\\s+Signature=(?<" + AUTH_HEADER_PATTERN_SIGNATURE_GROUP + ">[a-fA-F\\d]{1,256})", Pattern.CASE_INSENSITIVE);

    private final SigningAlgorithm algorithm;
    private final String accessKey;
    private final String date;
    private final Optional<String> region;
    private final String service;
    private final String signedheaders;
    private final String signature;

    public ParsedAuthHeader(SigningAlgorithm algorithm, String accessKey, String date, String region, String service, String signedheaders, String signature) {
        this.algorithm = algorithm;
        this.accessKey = accessKey;
        this.date = date;
        this.region = Optional.ofNullable(region);
        this.service = service;
        this.signedheaders = signedheaders;
        this.signature = signature;

    }

    public SigningAlgorithm getAlgorithm() {
        return algorithm;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public String getDate() {
        return date;
    }

    public Optional<String> getRegion() {
        return region;
    }

    public String getService() {
        return service;
    }

    public String getSignedHeaders() {
        return signedheaders;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + Objects.hashCode(this.algorithm);
        hash = 37 * hash + Objects.hashCode(this.accessKey);
        hash = 37 * hash + Objects.hashCode(this.date);
        hash = 37 * hash + Objects.hashCode(this.region);
        hash = 37 * hash + Objects.hashCode(this.service);
        hash = 37 * hash + Objects.hashCode(this.signedheaders);
        hash = 37 * hash + Objects.hashCode(this.signature);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ParsedAuthHeader other = (ParsedAuthHeader) obj;
        if (!Objects.equals(this.algorithm, other.algorithm)) {
            return false;
        }
        if (!Objects.equals(this.accessKey, other.accessKey)) {
            return false;
        }
        if (!Objects.equals(this.date, other.date)) {
            return false;
        }
        if (!Objects.equals(this.region, other.region)) {
            return false;
        }
        if (!Objects.equals(this.service, other.service)) {
            return false;
        }
        if (!Objects.equals(this.signedheaders, other.signedheaders)) {
            return false;
        }
        if (!Objects.equals(this.signature, other.signature)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "ParsedAuthHeader{" + "algorithm=" + algorithm + ", accessKey=" + accessKey + ", date=" + date + ", region=" + region + ", service=" + service + ", signedheaders=" + signedheaders + ", signature=" + signature + '}';
    }

    public static Optional<ParsedAuthHeader> parseFromAuthorizationHeader(String authHeader) {
        //Get the parts from the Authorization header
        Matcher authorizationMatcher = AUTH_HEADER_PATTERN.matcher(authHeader);

        if (!authorizationMatcher.matches()) {
            //Something is wrong. Why didn't this match now... when it already matched?
            LogWriter.logDebug("Unable to parse authorization headers. Input header: " + authHeader);
            return Optional.empty();
        }

        //Pull apart the string into components we want
        String algorithmString = authorizationMatcher.group(AUTH_HEADER_PATTERN_ALGORITHM_GROUP);
        Optional<SigningAlgorithm> algorithmOptional = SigningAlgorithm.fromAuthorizationHeaderString(algorithmString);
        if (algorithmOptional.isEmpty()) {
            LogWriter.logError("Unable to detect AWS signature type. Input header: " + authHeader + " Parsed algorithm: " + algorithmString);
            return Optional.empty();
        }
        String accessKey = authorizationMatcher.group(AUTH_HEADER_PATTERN_ACCESS_KEY_GROUP);
        String date = authorizationMatcher.group(AUTH_HEADER_PATTERN_DATE_GROUP);
        String region = authorizationMatcher.group(AUTH_HEADER_PATTERN_REGION_GROUP);
        String service = authorizationMatcher.group(AUTH_HEADER_PATTERN_SERVICE_GROUP);
        String signedheaders = authorizationMatcher.group(AUTH_HEADER_PATTERN_SIGNED_HEADERS_GROUP);
        String signature = authorizationMatcher.group(AUTH_HEADER_PATTERN_SIGNATURE_GROUP);

        //make return object and be done
        ParsedAuthHeader parsed = new ParsedAuthHeader(algorithmOptional.get(), accessKey, date, region, service, signedheaders, signature);
        LogWriter.logInfo("Successfully parsed Authorization header: " + parsed);
        return Optional.of(parsed);
    }

}
