package com.netspi.awssigner.signing;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ParsedAuthHeaderTest {

    @Test
    public void testTypical1CommaAnd1Space() {
        String testHeader = "Authorization: AWS4-HMAC-SHA256 Credential=ASIAXXXXXXXXXXXXXXXX/20230901/us-east-1/XXXX/aws4_request SignedHeaders=content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target, Signature=64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464";
        //Parse the header
        Optional<ParsedAuthHeader> result = ParsedAuthHeader.parseFromAuthorizationHeader(testHeader);
        //Ensure it parsed successfully.
        assertTrue(result.isPresent());
        //Extract the result
        ParsedAuthHeader parsedHeader = result.get();

        //Ensure all fields were extracted properly.
        assertEquals(SigningAlgorithm.SIGV4,parsedHeader.getAlgorithm());
        assertEquals("ASIAXXXXXXXXXXXXXXXX",parsedHeader.getAccessKey());
        assertEquals("20230901",parsedHeader.getDate());
        assertEquals("us-east-1",parsedHeader.getRegion().get());
        assertEquals("XXXX",parsedHeader.getService());
        assertEquals("content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target",parsedHeader.getSignedHeaders());
        assertEquals("64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464",parsedHeader.getSignature());
    }

    @Test
    public void testNoCommaAnd1Space() {
        String testHeader = "Authorization: AWS4-HMAC-SHA256 Credential=ASIAXXXXXXXXXXXXXXXX/20230901/us-east-1/XXXX/aws4_request SignedHeaders=content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target Signature=64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464";
        //Parse the header
        Optional<ParsedAuthHeader> result = ParsedAuthHeader.parseFromAuthorizationHeader(testHeader);
        //Ensure it parsed successfully.
        assertTrue(result.isPresent());
        //Extract the result
        ParsedAuthHeader parsedHeader = result.get();

        //Ensure all fields were extracted properly.
        assertEquals(SigningAlgorithm.SIGV4,parsedHeader.getAlgorithm());
        assertEquals("ASIAXXXXXXXXXXXXXXXX",parsedHeader.getAccessKey());
        assertEquals("20230901",parsedHeader.getDate());
        assertEquals("us-east-1",parsedHeader.getRegion().get());
        assertEquals("XXXX",parsedHeader.getService());
        assertEquals("content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target",parsedHeader.getSignedHeaders());
        assertEquals("64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464",parsedHeader.getSignature());
    }

    @Test
    public void test1CommaAndNoSpace() {
        String testHeader = "Authorization: AWS4-HMAC-SHA256 Credential=ASIAXXXXXXXXXXXXXXXX/20230901/us-east-1/XXXX/aws4_request SignedHeaders=content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target,Signature=64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464";
        //Parse the header
        Optional<ParsedAuthHeader> result = ParsedAuthHeader.parseFromAuthorizationHeader(testHeader);
        //Ensure it parsed successfully.
        assertTrue(result.isPresent());
        //Extract the result
        ParsedAuthHeader parsedHeader = result.get();

        //Ensure all fields were extracted properly.
        assertEquals(SigningAlgorithm.SIGV4,parsedHeader.getAlgorithm());
        assertEquals("ASIAXXXXXXXXXXXXXXXX",parsedHeader.getAccessKey());
        assertEquals("20230901",parsedHeader.getDate());
        assertEquals("us-east-1",parsedHeader.getRegion().get());
        assertEquals("XXXX",parsedHeader.getService());
        assertEquals("content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target",parsedHeader.getSignedHeaders());
        assertEquals("64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464",parsedHeader.getSignature());
    }
    @Test
    public void testManyCommasAnd1Space() {
        String testHeader = "Authorization: AWS4-HMAC-SHA256 Credential=ASIAXXXXXXXXXXXXXXXX/20230901/us-east-1/XXXX/aws4_request SignedHeaders=content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target,,,,,,,,,,,,, Signature=64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464";
        //Parse the header
        Optional<ParsedAuthHeader> result = ParsedAuthHeader.parseFromAuthorizationHeader(testHeader);
        //Ensure it parsed successfully.
        assertTrue(result.isPresent());
        //Extract the result
        ParsedAuthHeader parsedHeader = result.get();

        //Ensure all fields were extracted properly.
        assertEquals(SigningAlgorithm.SIGV4,parsedHeader.getAlgorithm());
        assertEquals("ASIAXXXXXXXXXXXXXXXX",parsedHeader.getAccessKey());
        assertEquals("20230901",parsedHeader.getDate());
        assertEquals("us-east-1",parsedHeader.getRegion().get());
        assertEquals("XXXX",parsedHeader.getService());
        assertEquals("content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target",parsedHeader.getSignedHeaders());
        assertEquals("64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464",parsedHeader.getSignature());
    }
    @Test
    public void testManyCommasAndNoSpace() {
        String testHeader = "Authorization: AWS4-HMAC-SHA256 Credential=ASIAXXXXXXXXXXXXXXXX/20230901/us-east-1/XXXX/aws4_request SignedHeaders=content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target,,,,,,,,,,,,,Signature=64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464";
        //Parse the header
        Optional<ParsedAuthHeader> result = ParsedAuthHeader.parseFromAuthorizationHeader(testHeader);
        //Ensure it parsed successfully.
        assertTrue(result.isPresent());
        //Extract the result
        ParsedAuthHeader parsedHeader = result.get();

        //Ensure all fields were extracted properly.
        assertEquals(SigningAlgorithm.SIGV4,parsedHeader.getAlgorithm());
        assertEquals("ASIAXXXXXXXXXXXXXXXX",parsedHeader.getAccessKey());
        assertEquals("20230901",parsedHeader.getDate());
        assertEquals("us-east-1",parsedHeader.getRegion().get());
        assertEquals("XXXX",parsedHeader.getService());
        assertEquals("content-encoding;host;x-amz-date;x-amz-requestsupertrace;x-amz-target",parsedHeader.getSignedHeaders());
        assertEquals("64ed7bf1ee17050e2a38b4c878ca6471c341b78cdb428bcec52cc6b58f1a8464",parsedHeader.getSignature());
    }


}
