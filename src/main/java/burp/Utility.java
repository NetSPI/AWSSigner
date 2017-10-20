package burp;

import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.sun.deploy.util.StringUtils;
import uk.co.lucasweb.aws.v4.signer.Header;
import uk.co.lucasweb.aws.v4.signer.HttpRequest;
import uk.co.lucasweb.aws.v4.signer.Signer;
import uk.co.lucasweb.aws.v4.signer.credentials.AwsCredentials;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utility {

    private IExtensionHelpers helpers;

    public static byte[] signRequest(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, String service, String region, String accessKey, String secretKey) throws Exception {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

        List<String> headers = requestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<String>(headers);
        headers.remove(0);

        Map<String, String> headerMap = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);

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
        amz.setTimeZone(TimeZone.getTimeZone("GMT"));
        String amzdate = amz.format(new Date());

        SimpleDateFormat dateStamp = new SimpleDateFormat("yyyyMMdd");
        String dateStampString = dateStamp.format(new Date());

        headerMap.put("x-amz-date",amzdate);

        String signedHeaders = getSignedHeaders(headerMap.get("authorization"));

        String[] signedHeaderArray = signedHeaders.split(";");

        List<String> signedHeaderList = Arrays.asList(signedHeaderArray);

        Collections.sort(signedHeaderList);

        String canonicalHeaders = "";

        for (String signedHeader : signedHeaderList){
            canonicalHeaders = canonicalHeaders + signedHeader.toLowerCase() + ':' + headerMap.get(signedHeader) + '\n';
        }

        byte[] request = messageInfo.getRequest();
        String body = "";
        String payloadHash = "";

        if (!requestInfo.getMethod().equals("GET")){

            int bodyOffset = requestInfo.getBodyOffset();
            body = new String(request, bodyOffset, request.length - bodyOffset, "UTF-8").trim();
            payloadHash = Hashing.sha256().hashString(body, StandardCharsets.UTF_8).toString().toLowerCase();

        } else {
            payloadHash = Hashing.sha256().hashString("", StandardCharsets.UTF_8).toString().toLowerCase();
        }

        String canonicalURI = requestInfo.getUrl().getPath();

        String canonicalQueryString = requestInfo.getUrl().getQuery();

        if (Strings.isNullOrEmpty(canonicalQueryString)){
            canonicalQueryString = "";
        }


        String canonicalRequest  = requestInfo.getMethod() + '\n' + canonicalURI + '\n' + canonicalQueryString + '\n' +
                canonicalHeaders +'\n' + signedHeaders + '\n' + payloadHash;

        String credScope = dateStampString + '/' + region + '/' + service + '/' + "aws4_request";

        String algorithm = "AWS4-HMAC-SHA256";

        String stringToSign = algorithm + '\n' + amzdate + '\n' + credScope + '\n' + Hashing.sha256().hashString(canonicalRequest, StandardCharsets.UTF_8).toString().toLowerCase();

        byte[] signingKey = getSignatureKey(secretKey, dateStampString, region, service);

        String signature = DatatypeConverter.printHexBinary(HmacSHA256(stringToSign, signingKey));

        newHeaders.add("Authorization: " + algorithm + ' ' + "Credential=" + accessKey + '/' + credScope + ", " + "SignedHeaders=" +
                signedHeaders + ", " + "Signature=" + signature.toLowerCase());
        newHeaders.add("X-Amz-Date: " + amzdate);

        byte[] signedRequest = helpers.buildHttpMessage(newHeaders, body.getBytes());

        return signedRequest;
    }

    static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        byte[] kSigning = HmacSHA256("aws4_request", kService);
        return kSigning;
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
