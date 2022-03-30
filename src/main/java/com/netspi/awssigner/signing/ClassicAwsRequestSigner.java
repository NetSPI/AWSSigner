package com.netspi.awssigner.signing;

import com.google.common.base.Strings;
import com.google.common.hash.Hashing;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.Profile;
import java.util.*;
/**
 * As much as possible this signer copy-pastes the code from V1 and should have
 * the same output. Hopefully there aren't any differences
 */
public class ClassicAwsRequestSigner implements AwsRequestSigner {

    private final IExtensionHelpers helpers;
    private final Profile profile;

    public ClassicAwsRequestSigner(IExtensionHelpers helpers, Profile profile) {
        this.helpers = helpers;
        this.profile = profile;
    }

    @Override
    public byte[] sign(IHttpRequestResponse messageInfo, IRequestInfo requestInfo, ParsedAuthHeader parsedAuthorizationHeader) throws SigningException {
        //Get the credentials for signing
        SigningCredentials credentials;
        try {
            credentials = profile.getCredentials();
        } catch (SignerCredentialException ex) {
            final String errorMessage = "Unable to fetch credentials for profile " + profile + " when attempting to sign. Error: " + ex.getMessage();
            LogWriter.logError(errorMessage);
            throw new SigningException(errorMessage, ex);
        }
        //Pull out the creds using variable names/formats for V1 code
        String accessKey = credentials.getAccessKey();
        String secretKey = credentials.getSecretKey();
        String token = credentials.getSessionToken().orElse(""); //default to empty string

        //May be set in profile, fall back to parsed auth header
        String service = profile.getService().orElse(parsedAuthorizationHeader.getService());
        String region = profile.getRegion().orElse(parsedAuthorizationHeader.getRegion().orElseThrow(()-> new SigningException("Region missing from Authorization header. Is this a SigV4a request? Can't sign with classic signer")));

        try {
            return callV1Signing(messageInfo, helpers, service, region, accessKey, secretKey, token);
        } catch (Exception ex) {
            final String errorMessage = "Unable to sign request with profile " + profile + " using V1 signing algorithm. Error: " + ex.getMessage();
            LogWriter.logError(errorMessage);
            throw new SigningException(errorMessage, ex);
        }
    }
    
    //As much as possible, copy-pasting from V1
    private byte[] callV1Signing(IHttpRequestResponse messageInfo,
                              IExtensionHelpers helpers,
                              String service,
                              String region,
                              String accessKey,
                              String secretKey,
                              String token) throws Exception {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = requestInfo.getHeaders();
        if (!token.isEmpty()) {
            boolean tokenExists = false;
            int i = 0;
            for (String header : headers) {
                if (header.toLowerCase().startsWith("x-amz-security-token")) {
                    headers.set(i, "X-Amz-Security-Token: " + token);
                    tokenExists = true;
                }
                i++;
            }
            if (!tokenExists)
                headers.add("X-Amz-Security-Token: " + token);
        }
        List<String> newHeaders = new ArrayList<>(headers);
        headers.remove(0);

        Map<String, String> headerMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        String authHeader = "";
        String amzDate = "";

        for (String header : headers) {
            if (header.toLowerCase().startsWith("authorization:")){
                authHeader = header;
            }
            if (header.toLowerCase().startsWith("x-amz-date:")){
                amzDate = header;
            }

            String[] headerPair = header.split(":",2);
            headerMap.put(headerPair[0].trim(),headerPair[1].trim());
        }

        headers.remove(authHeader);
        headers.remove(amzDate);
        newHeaders.remove(authHeader);
        newHeaders.remove(amzDate);

        SimpleDateFormat amz = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        amz.setTimeZone(TimeZone.getTimeZone("UTC"));
        String amzdate = amz.format(new Date());

        SimpleDateFormat dateStamp = new SimpleDateFormat("yyyyMMdd");
        dateStamp.setTimeZone(TimeZone.getTimeZone("UTC"));
        String dateStampString = dateStamp.format(new Date());

        headerMap.put("x-amz-date",amzdate);

        String signedHeaders = getSignedHeaders(headerMap.get("authorization"));
        if (!token.isEmpty() && !signedHeaders.contains("x-amz-security-token")) {
            signedHeaders = signedHeaders + ";x-amz-security-token";
        }

        String[] signedHeaderArray = signedHeaders.split(";");

        List<String> signedHeaderList = Arrays.asList(signedHeaderArray);

        Collections.sort(signedHeaderList);

        StringBuilder canonicalHeaders = new StringBuilder();

        for (String signedHeader : signedHeaderList) {
            if (headerMap.containsKey(signedHeader)) {
                canonicalHeaders.append(signedHeader.toLowerCase()).append(':').append(headerMap.get(signedHeader)).append('\n');
            } else {
                LogWriter.logInfo("Warning: SignedHeader '" + signedHeader + "' does not exist in request headers.");
            }
        }
        String signedHeadersSorted = String.join(";", signedHeaderList);
        LogWriter.logDebug(canonicalHeaders.toString());
        byte[] request = messageInfo.getRequest();
        String body = "";
        String notUnicode = "[^\\u0000-\\u007F]+";
        String payloadHash;

        if (!requestInfo.getMethod().equals("GET") || requestInfo.getBodyOffset() > 0){

            int bodyOffset = requestInfo.getBodyOffset();
            body = hexToString(bytesToHex(Arrays.copyOfRange(request, bodyOffset, request.length)));
            if(!body.matches(notUnicode)) {
                char[] chars = body.toCharArray();
                String sanitize = "";
                for (char aChar : chars) {
                    String test = Character.toString(aChar);
                    if (Pattern.matches(notUnicode, test)) {
                        sanitize = sanitize.concat(URLEncoder.encode(test, StandardCharsets.UTF_8.toString()));
                    } else {
                        sanitize = sanitize.concat(test);
                    }
                }
                body = sanitize;
            }
            LogWriter.logDebug(Base64.getEncoder().encodeToString(body.getBytes("utf-8")));
            payloadHash = Hashing.sha256().hashString(body, StandardCharsets.UTF_8).toString().toLowerCase();

        } else {
            payloadHash = Hashing.sha256().hashString("", StandardCharsets.UTF_8).toString().toLowerCase();
        }

        String canonicalUri = requestInfo.getUrl().getPath();
        if(!canonicalUri.matches(notUnicode)) {
            char[] chars = canonicalUri.toCharArray();
            String sanitize = "";
            for (char aChar : chars) {
                String test = Character.toString(aChar);
                if (Pattern.matches(notUnicode, test)) {
                    sanitize = sanitize.concat(URLEncoder.encode(test, StandardCharsets.UTF_8.toString()));
                } else {
                    sanitize = sanitize.concat(test);
                }
            }
            canonicalUri = sanitize;
        }
        LogWriter.logDebug(canonicalUri);
        URI uri = new URI(canonicalUri);
        uri = uri.normalize();
        String path = uri.getPath();
        if(canonicalUri.contains("%")) {
            path = uri.getRawPath();
        }
        String[] segments = path.split("/");
        String[] encodedSegments = new String[segments.length];
        for (int i=0; i<segments.length; i++) {
            encodedSegments[i] = URLEncoder.encode(segments[i], StandardCharsets.UTF_8.toString())
                    .replace("+", "%20").replace("*", "%2A")
                    .replace("%7E", "~");
        }

        String encodedCanonicalUri = String.join("/", encodedSegments);
        LogWriter.logDebug(encodedCanonicalUri);

        // Replace characters we might have lost in the split
        if (path.charAt(path.length()-1) == '/') {
            encodedCanonicalUri = encodedCanonicalUri + "/";
        }

        String canonicalQueryString = requestInfo.getUrl().getQuery();
        if (Strings.isNullOrEmpty(canonicalQueryString)){
            canonicalQueryString = "";
        }
        if(!canonicalQueryString.matches(notUnicode)) {
            char[] chars = canonicalQueryString.toCharArray();
            String sanitize = "";
            for (char aChar : chars) {
                String test = Character.toString(aChar);
                if (Pattern.matches(notUnicode, test)) {
                    sanitize = sanitize.concat(URLEncoder.encode(test, StandardCharsets.UTF_8.toString()));
                } else {
                    sanitize = sanitize.concat(test);
                }
            }
            canonicalQueryString = sanitize;
        }

        String[] sorted = canonicalQueryString.split("&");
        Arrays.sort(sorted);

        for (int i = 0; i < sorted.length; ++i) {
            String[] param = sorted[i].split("=");
            for (int j = 0; j < param.length; ++j) {
                try {
                    param[j] = URLEncoder.encode(param[j], StandardCharsets.UTF_8.toString())
                            // OAuth encodes some characters differently:
                            .replace("+", "%20").replace("*", "%2A")
                            .replace("%7E", "~").replace("%25", "%");
                    // This could be done faster with more hand-crafted code.
                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
            if (param.length > 1) {
                sorted[i] = String.join("=", param);
            } else if (param.length == 1 && !param[0].isEmpty()){
                sorted[i] = param[0] + "=";
            }
        }
        canonicalQueryString = String.join("&", sorted);

        String[] cleanup = canonicalQueryString.split("");
        for (int i = 0; i < cleanup.length; ++i) {
            if (cleanup[i].equals("%")) {
                cleanup[i+1] = cleanup[i+1].toUpperCase();
                cleanup[i+2] = cleanup[i+2].toUpperCase();
            }
        }
        canonicalQueryString = String.join("", cleanup);
        LogWriter.logDebug(canonicalQueryString);
        //canonicalQueryString = canonicalQueryString.replace(":","%3A").replace("/","%2F").replace(" ", "%20");

        String canonicalRequest  = requestInfo.getMethod() + '\n' + encodedCanonicalUri + '\n' + canonicalQueryString + '\n' +
                canonicalHeaders +'\n' + signedHeadersSorted + '\n' + payloadHash;
        String credScope = dateStampString + '/' + region + '/' + service + '/' + "aws4_request";
        String algorithm = "AWS4-HMAC-SHA256";

        String stringToSign = algorithm + '\n' + amzdate + '\n' + credScope + '\n' + Hashing.sha256().hashString(canonicalRequest, StandardCharsets.UTF_8).toString().toLowerCase();
        LogWriter.logDebug(canonicalRequest);
        LogWriter.logDebug(stringToSign);
        byte[] signingKey = getSignatureKey(secretKey, dateStampString, region, service);

        String signature = bytesToHex(HmacSHA256(stringToSign, signingKey));

        newHeaders.add("Authorization: " + algorithm + ' ' + "Credential=" + accessKey + '/' + credScope + ", " + "SignedHeaders=" +
                signedHeadersSorted + ", " + "Signature=" + signature.toLowerCase());
        newHeaders.add("X-Amz-Date: " + amzdate);
        if(!newHeaders.get(0).matches(notUnicode)) {
            char[] chars = newHeaders.get(0).toCharArray();
            String sanitize = "";
            for (char aChar : chars) {
                String test = Character.toString(aChar);
                if (Pattern.matches(notUnicode, test)) {
                    sanitize = sanitize.concat(URLEncoder.encode(test, StandardCharsets.UTF_8.toString()));
                } else {
                    sanitize = sanitize.concat(test);
                }
            }
            newHeaders.set(0, sanitize);
        }

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }

    private byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        return HmacSHA256("aws4_request", kService);
    }

    private String getSignedHeaders(String authHeader) {

        String signedHeaders = "";

        Pattern pattern = Pattern.compile("SignedHeaders=(.*?)[,\\s]");

        Matcher matcher = pattern.matcher(authHeader);
        if (matcher.find()) {
            signedHeaders = matcher.group(1);
        }

        return signedHeaders;

    }

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();
    private String bytesToHex(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    private String hexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length() - 1; i += 2) {
            String output = hex.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char) decimal);
        }
        return sb.toString();
    }


}
