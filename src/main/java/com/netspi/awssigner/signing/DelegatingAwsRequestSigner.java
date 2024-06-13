package com.netspi.awssigner.signing;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentialConverter;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.Profile;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.Aws4UnsignedPayloadSigner;
import software.amazon.awssdk.auth.signer.AwsS3V4Signer;
import software.amazon.awssdk.auth.signer.AwsSignerExecutionAttribute;
import software.amazon.awssdk.auth.signer.S3SignerExecutionAttribute;
import software.amazon.awssdk.authcrt.signer.AwsCrtS3V4aSigner;
import software.amazon.awssdk.authcrt.signer.AwsCrtV4aSigner;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.signer.Signer;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.internal.util.RegionScope;

/**
 * Passes off request signing responsibility to the AWS SDK.
 */
public class DelegatingAwsRequestSigner implements AwsRequestSigner {

    private final IExtensionHelpers helpers;
    private final Profile profile;

    public DelegatingAwsRequestSigner(IExtensionHelpers helpers, Profile profile) {
        this.helpers = helpers;
        this.profile = profile;
    }

    @Override
    public byte[] sign(IHttpRequestResponse messageInfo, IRequestInfo request, ParsedAuthHeader authHeader) throws SigningException {
        //Get the credentials for signing
        SigningCredentials credentials;
        try {
            credentials = profile.getCredentials();
        } catch (SignerCredentialException ex) {
            final String errorMessage = "Unable to fetch credentials for profile " + profile + " when attempting to sign. Error: " + ex.getMessage();
            LogWriter.logError(errorMessage);
            throw new SigningException(errorMessage, ex);
        }

        //May be set in profile, fall back to parsed auth header
        String service = profile.getService().orElse(authHeader.getService());

        //Get the fulll request as bytes
        byte[] originalRequestBytes = messageInfo.getRequest();

        //Pull out the bytes of the body
        final byte[] body = Arrays.copyOfRange(originalRequestBytes, request.getBodyOffset(), originalRequestBytes.length);

        //Get all the headers
        List<String> allHeaders = request.getHeaders();
        LogWriter.logDebug("All headers in request: " + allHeaders);
        //First line is HTTP request line (GET / ...). Take it out
        final String originalRequestLine = allHeaders.remove(0);

        //Split the signed headers in the auth header into individual headers.
        String signedHeadersString = authHeader.getSignedHeaders();
        LogWriter.logDebug("Signed Headers extracted from Authorization header: " + signedHeadersString);
        Set<String> originalSignedHeaderSet = Arrays.stream(signedHeadersString.split(";"))
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        LogWriter.logDebug("Signed Headers extracted from Authorization header, after splitting: " + originalSignedHeaderSet);

        //For each signed header, we need get the corresponding value(s) in our request. 
        Map<String, List<String>> signedHeaderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (final String signedHeader : originalSignedHeaderSet) {
            List<String> headerValues = allHeaders.stream().filter(header -> {
                //Check if this line matches the signed header
                return header.toLowerCase().startsWith(signedHeader + ":");
            }).map(header -> {
                //Only keep the header's value.
                //We know from the filter that there is a colon character, so this is safe.
                return header.split(":", 2)[1];
            }).collect(Collectors.toList());
            LogWriter.logDebug("For header \"" + signedHeader + "\" found the following values: " + headerValues);
            signedHeaderMap.put(signedHeader, headerValues);
        }
        LogWriter.logDebug("signedHeaderMap: " + signedHeaderMap);

        //Check header for UNSIGNED-PAYLOAD, indicating auth type v4-unsigned-body is used. There may be other possible indicators.
        boolean unsignedBodyType = false;
        for(List<String> value: signedHeaderMap.values()){
            if (value.contains("UNSIGNED-PAYLOAD")){
                    unsignedBodyType = true;
            }
        }
        
        //Build request object for signing
        URI uri;
        try {
            uri = request.getUrl().toURI();
            LogWriter.logDebug("Identified target URI as: " + uri);
        } catch (URISyntaxException ex) {
            final String errorMessage = "Bad Request URL. Not valid syntax. Error: " + ex.getMessage();
            LogWriter.logError(errorMessage);
            throw new SigningException(errorMessage, ex);
        }

        String targetURLHost = uri.getHost();
        LogWriter.logDebug("Extracted host value from target URI as: " + targetURLHost);

        //Get the original host header. 
        String originalHost = null;
        int originalHostPort = -1;
        for (String header : allHeaders) {
            if (header.toLowerCase().startsWith("host:")) {
                String originalHostHeaderValue = header.replaceFirst("(?i)host:", "").trim();
                LogWriter.logDebug("Extracted host header value from original headers as: " + originalHostHeaderValue);
                if (originalHostHeaderValue.contains(":")) {
                    String[] originalHostHeaderParts = originalHostHeaderValue.split(":", 2);
                    originalHost = originalHostHeaderParts[0];
                    originalHostPort = Integer.parseInt(originalHostHeaderParts[1]);
                } else {
                    originalHost = originalHostHeaderValue;
                }
                break;
            }
        }

        //If we can't find the host header, use what's in the URI
        if (originalHost == null || originalHost.isEmpty()) {
            originalHost = uri.getHost();
            originalHostPort = uri.getPort();
            LogWriter.logInfo("No host header value found in original headers. Falling back to value from URI: " + targetURLHost);
        }

        // If the value of the host header doesn't match the value in the target URL, we need to swap the host header value into the URL
        // This maintains compatibility with SignerV1 and supports proxies where the URL may point to a localhost endpoint, 
        // but the request gets forwarded onto a real AWS endpoint. The host header must be the real AWS endpoint and the SigV4 signature must match
        // even though the URL has the proxy endpoint. 
        if (!targetURLHost.equals(originalHost)) {
            try {
                uri = new URI(uri.getScheme(), uri.getUserInfo(), originalHost, originalHostPort, uri.getPath(), uri.getQuery(), uri.getFragment());
                LogWriter.logDebug("Updated URI for signing as: " + uri);
            } catch (URISyntaxException ex) {
                final String errorMessage = "Bad Request URL after update to original host \"" + originalHost + "\". Not valid syntax. Error: " + ex.getMessage();
                LogWriter.logError(errorMessage);
                throw new SigningException(errorMessage, ex);
            }
        }

        // Need to remove these headers for the SDK
        signedHeaderMap.remove("x-amz-security-token");
        signedHeaderMap.remove("x-amz-date");
        signedHeaderMap.remove("host");
        //Check if this is an S3 request.
        if (service.equalsIgnoreCase("s3")) {
            //Also remove this header
            signedHeaderMap.remove("x-amz-content-sha256");
        }
        LogWriter.logDebug("signedHeaderMap after removals for SDK: " + signedHeaderMap);

        SdkHttpFullRequest signedRequest;
        try {
            final SdkHttpFullRequest awsRequest = SdkHttpFullRequest.builder()
                    .headers(signedHeaderMap)
                    .uri(uri)
                    .method(SdkHttpMethod.fromValue(request.getMethod()))
                    .contentStreamProvider(() -> new ByteArrayInputStream(body)).build();

            //Convert signing creds to AWS type
            AwsCredentials awsCredentials = new SigningCredentialConverter(credentials).resolveCredentials();

            //Check if the headers include a "X-Amz-Region-Set" header value
            Optional<String> xAmzRegionSetHeaderValue = allHeaders.stream().filter(headerLine -> {
                return headerLine.toLowerCase().startsWith("x-amz-region-set:");
            })
                    .map(header -> {
                        //Only keep the header's value.
                        //We know from the filter that there is a colon character, so this is safe.
                        return header.split(":", 2)[1];
                    }).findFirst();

            //We want to find the right region for our request
            //May be set in the profile, fall back to parsed auth header, then fall back to X-Amz-Region-Set header.
            //If it's not set any of those places... don't know what to do.
            String region = profile.getRegion().orElse(authHeader.getRegion().orElse(xAmzRegionSetHeaderValue.orElse(null)));

            //Get the metadata for signing
            ExecutionAttributes executionAttributes = new ExecutionAttributes();
            executionAttributes.putAttribute(AwsSignerExecutionAttribute.AWS_CREDENTIALS, awsCredentials);
            executionAttributes.putAttribute(AwsSignerExecutionAttribute.SERVICE_SIGNING_NAME, service);
            LogWriter.logDebug("Adding service (" + AwsSignerExecutionAttribute.SERVICE_SIGNING_NAME + ") attribute: " + service);
            executionAttributes.putAttribute(AwsSignerExecutionAttribute.SIGNING_REGION, Region.of(region));
            LogWriter.logDebug("Adding region (" + AwsSignerExecutionAttribute.SIGNING_REGION + ") attribute: " + Region.of(region));

            //We'll now create the appropriate signer
            Signer signer;

            //Check if this is an S3 request. They get special handling
            if (service.equalsIgnoreCase("s3")) {
                LogWriter.logDebug("Handling S3-specific signature.");
                executionAttributes.putAttribute(AwsSignerExecutionAttribute.SIGNER_DOUBLE_URL_ENCODE, false);
                executionAttributes.putAttribute(S3SignerExecutionAttribute.ENABLE_PAYLOAD_SIGNING, true);
                if (authHeader.getAlgorithm() == SigningAlgorithm.SIGV4A) {
                    LogWriter.logDebug("Handling S3-specific SigV4a signature.");
                    if (region.equals("*")) {
                        LogWriter.logDebug("Handling region * with SigV4A");
                        executionAttributes.putAttribute(AwsSignerExecutionAttribute.SIGNING_REGION_SCOPE, RegionScope.GLOBAL);
                        LogWriter.logDebug("Adding region scope (" + AwsSignerExecutionAttribute.SIGNING_REGION_SCOPE + ") attribute: " + RegionScope.GLOBAL);
                    }
                    signer = AwsCrtS3V4aSigner.create();
                } else {
                    LogWriter.logDebug("Handling S3-specific SigV4 signature.");
                    signer = AwsS3V4Signer.create();
                }

            } else {
                LogWriter.logDebug("Handling non-S3 signature.");
                executionAttributes.putAttribute(AwsSignerExecutionAttribute.SIGNER_DOUBLE_URL_ENCODE, true);
                if (authHeader.getAlgorithm() == SigningAlgorithm.SIGV4A) {
                    LogWriter.logDebug("Handling non-S3 SigV4a signature.");
                    signer = AwsCrtV4aSigner.create();
                } else if (unsignedBodyType) {
                    LogWriter.logDebug("Handling unsigned payload SigV4 signature.");
                    signer = Aws4UnsignedPayloadSigner.create();
                } else {
                    LogWriter.logDebug("Handling non-S3 SigV4 signature.");
                    signer = Aws4Signer.create();
                }
            }
            LogWriter.logDebug("Execution attributes: " + executionAttributes.getAttributes());
            signedRequest = signer.sign(awsRequest, executionAttributes);

        } catch (RuntimeException ex) {
            final String errorMessage = "Unable to sign request with AWS SDK. Error: " + ex.getMessage();
            LogWriter.logError(errorMessage);
            throw new SigningException(errorMessage, ex);
        }
        LogWriter.logDebug("Successfully signed request with AWS signer.");

        //Rebuild the final headers
        List<String> finalHeaders = new ArrayList<>(allHeaders);
        final Map<String, List<String>> postSignedHeaders = signedRequest.headers();
        LogWriter.logDebug("Signed headers after signing: " + postSignedHeaders);

        //Merge back in the signed headers with updated values
        for (final String signedHeader : postSignedHeaders.keySet()) {
            List<String> signedValues = postSignedHeaders.get(signedHeader);
            //Iterate through the list of headers, searching for a match for the signed header.
            //Track the value in case there are multiple values so we know which to pick.
            for (int i = 0, valueCount = 0; i < finalHeaders.size(); i++) {
                String finalHeaderLine = finalHeaders.get(i);
                if (finalHeaderLine.toLowerCase().startsWith(signedHeader.toLowerCase() + ":")) {
                    String[] parts = finalHeaderLine.split(":", 2);
                    finalHeaders.set(i, parts[0] + ": " + signedValues.get(valueCount));
                    valueCount++;
                }
            }
        }
        LogWriter.logDebug("All request headers after merging in signed headers: " + finalHeaders);

        //Special handling for Content-MD5
        for (int i = 0; i < finalHeaders.size(); i++) {
            String finalHeader = finalHeaders.get(i);
            if (finalHeader.toLowerCase().startsWith("Content-MD5".toLowerCase() + ":")) {
                //Found Content-MD5 header. Update it.
                try {
                    final byte[] bodyMD5 = MessageDigest.getInstance("MD5").digest(body);
                    final String updatedContentMD5 = helpers.base64Encode(bodyMD5);
                    finalHeaders.set(i, "Content-MD5: " + updatedContentMD5);
                    LogWriter.logDebug("Updated Content-MD5 header");
                } catch (NoSuchAlgorithmException e) {
                    LogWriter.logError("Platform does not support MD5. Cannot update Content-MD5 header");
                }
            }
        }

        //Check if the credentials have a session token
        if (credentials.getSessionToken().isPresent()) {
            boolean foundHeader = false;
            for (int i = 0; i < finalHeaders.size(); i++) {
                String header = finalHeaders.get(i);
                //Check if this header is already the session token header
                if (header.toLowerCase().startsWith("x-amz-security-token:")) {
                    finalHeaders.set(i, "X-Amz-Security-Token: " + credentials.getSessionToken().get());
                    foundHeader = true;
                    LogWriter.logDebug("Replaced " + header + " in request with profile's session token.");
                }
            }
            if (!foundHeader) {
                finalHeaders.add("X-Amz-Security-Token: " + credentials.getSessionToken().get());
                LogWriter.logDebug("Added X-Amz-Security-Token to request with profile's session token.");
            }
        } else {
            for (Iterator<String> iterator = finalHeaders.iterator(); iterator.hasNext();) {
                String header = iterator.next();
                if (header.toLowerCase().startsWith("x-amz-security-token:")) {
                    iterator.remove();
                    LogWriter.logDebug("Removed " + header + " from request because it was signed with credentials which have a session token.");
                }
            }
        }

        LogWriter.logDebug("Final Headers: " + finalHeaders);

        //Handle the first request line
        //We actually want to rebuild this from the signed request because it would have handled URL encoding for us if necessary.
        String methodString = signedRequest.method().toString();
        URI signedUri = signedRequest.getUri();
        String signedPath = signedUri.getRawPath();
        String signedQuery = signedUri.getRawQuery() == null ? "" : "?" + signedUri.getRawQuery();
        String httpProtocolPart = originalRequestLine.substring(originalRequestLine.lastIndexOf(" ") + 1);
        String newRequestLine = methodString + " " + signedPath + signedQuery + " " + httpProtocolPart;
        finalHeaders.add(0, newRequestLine);

        //Build it and send it back
        return helpers.buildHttpMessage(finalHeaders, body);
    }

}
