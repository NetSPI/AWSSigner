package burp;

import com.google.common.base.Strings;
import com.google.common.hash.Hashing;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utility {

    public static byte[] signRequest(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, String service, String region, String accessKey, String secretKey) throws Exception {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

        List<String> headers = requestInfo.getHeaders();
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

        String[] signedHeaderArray = signedHeaders.split(";");

        List<String> signedHeaderList = Arrays.asList(signedHeaderArray);

        Collections.sort(signedHeaderList);

        StringBuilder canonicalHeaders = new StringBuilder();

        for (String signedHeader : signedHeaderList){
            canonicalHeaders.append(signedHeader.toLowerCase()).append(':').append(headerMap.get(signedHeader)).append('\n');
        }

        byte[] request = messageInfo.getRequest();
        String body = "";
        String payloadHash;

        if (!requestInfo.getMethod().equals("GET")){

            int bodyOffset = requestInfo.getBodyOffset();
            body = new String(request, bodyOffset, request.length - bodyOffset, "UTF-8").trim();
            payloadHash = Hashing.sha256().hashString(body, StandardCharsets.UTF_8).toString().toLowerCase();

        } else {
            payloadHash = Hashing.sha256().hashString("", StandardCharsets.UTF_8).toString().toLowerCase();
        }

        String canonicalUri = requestInfo.getUrl().getPath();

        // URI encode all path segments
        String[] segments = canonicalUri.split("/");
        String[] encodedSegments = new String[segments.length];
        for (int i=0; i<segments.length; i++) {
            encodedSegments[i] = URLEncoder.encode(segments[i], StandardCharsets.UTF_8.toString());
        }

        String encodedCanonicalUri = String.join("/", encodedSegments);

        // Replace characters we might have lost in the split
        if (canonicalUri.charAt(canonicalUri.length()-1) == '/') {
            encodedCanonicalUri = encodedCanonicalUri + "/";
        }

        String canonicalQueryString = requestInfo.getUrl().getQuery();

        if (Strings.isNullOrEmpty(canonicalQueryString)){
            canonicalQueryString = "";
        }

        canonicalQueryString = canonicalQueryString.replace(":","%3A").replace("/","%2F");

        String canonicalRequest  = requestInfo.getMethod() + '\n' + encodedCanonicalUri + '\n' + canonicalQueryString + '\n' +
                canonicalHeaders +'\n' + signedHeaders + '\n' + payloadHash;


        String credScope = dateStampString + '/' + region + '/' + service + '/' + "aws4_request";

        String algorithm = "AWS4-HMAC-SHA256";

        String stringToSign = algorithm + '\n' + amzdate + '\n' + credScope + '\n' + Hashing.sha256().hashString(canonicalRequest, StandardCharsets.UTF_8).toString().toLowerCase();

        byte[] signingKey = getSignatureKey(secretKey, dateStampString, region, service);

        String signature = DatatypeConverter.printHexBinary(HmacSHA256(stringToSign, signingKey));

        newHeaders.add("Authorization: " + algorithm + ' ' + "Credential=" + accessKey + '/' + credScope + ", " + "SignedHeaders=" +
                signedHeaders + ", " + "Signature=" + signature.toLowerCase());
        newHeaders.add("X-Amz-Date: " + amzdate);

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }

    private static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        return HmacSHA256("aws4_request", kService);
    }

    private static String getSignedHeaders(String authHeader){

        String signedHeaders = "";

        Pattern pattern = Pattern.compile("SignedHeaders=(.*?),");

        Matcher matcher = pattern.matcher(authHeader);
        if (matcher.find()){
            signedHeaders = matcher.group(1);
        }

        return  signedHeaders;

    }
}
