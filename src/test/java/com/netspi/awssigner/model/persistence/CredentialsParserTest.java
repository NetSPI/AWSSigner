package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.credentials.CredentialsParser;
import com.netspi.awssigner.credentials.SigningCredentials;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CredentialsParserTest {

    private final Path parentTestInputFolder = Paths.get("src", "test", "resources", "CredentialsParserInputs");

    @Test
    public void testSingleSimpleProfile() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertTrue(creds.getSessionToken().isEmpty());
    }

    @Test
    public void testSingleSimpleProfileWithSession() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_with_session.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4Olgk", creds.getSessionToken().get());
    }

    @Test
    public void testSettingsText() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("settings_text.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4Olgk", creds.getSessionToken().get());
    }

    @Test
    public void testGetSessionTokenOutput() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("get-session-token_output.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("mgJteE7dZgSLC2eo2vKsAUWRSnchrWzCRnoDpUSJ", creds.getSecretKey());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE", creds.getSessionToken().get());
    }

    @Test
    public void testExternalCommandOutput() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("external_command_example.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4Olgk", creds.getSessionToken().get());
    }

    @Test
    public void testEnvironmentVariablesCommands() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("environment_variables.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE", creds.getSessionToken().get());
    }

    @Test
    public void testCLIConfigure() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("cli_configure_example.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.getSecretKey());
        assertTrue(creds.getSessionToken().isEmpty());
    }

    @Test
    public void testAssumeRoleXMLOneLine() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("assume-role_output_xml_oneline.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("DcCc9H6oCkGUEXAMPLEx8NIfVG8kO2T/3jORxuZY", creds.getSecretKey());
        assertEquals("AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==", creds.getSessionToken().get());
    }

    @Test
    public void testAssumeRoleXMLMultiLine() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("assume-role_output_xml.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("AKIAIOSFODNN7EXAMPLE", creds.getAccessKey());
        assertEquals("DcCc9H6oCkGUEXAMPLEx8NIfVG8kO2T/3jORxuZY", creds.getSecretKey());
        assertEquals("AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==", creds.getSessionToken().get());
    }

    @Test
    public void testAssumeRoleJSONMultiLine() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("assume-role_output.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("ASIAJEXAMPLEXEG2JICA", creds.getAccessKey());
        assertEquals("FTNBND5Q6mEXAMPLEe27V0Pce/03EShqVZTTsLzF", creds.getSecretKey());
        assertEquals("AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=", creds.getSessionToken().get());
    }
    
    @Test
    public void testAssumeRoleJSONOneLine() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("assume-role_output_oneline.txt");
        byte[] bytes = Files.readAllBytes(inputPath);
        String rawText = new String(bytes, StandardCharsets.UTF_8);
        Optional<SigningCredentials> result = CredentialsParser.parseCredentialsFromText(rawText);
        assertTrue(result.isPresent());
        SigningCredentials creds = result.get();
        assertEquals("ASIAJEXAMPLEXEG2JICA", creds.getAccessKey());
        assertEquals("FTNBND5Q6mEXAMPLEe27V0Pce/03EShqVZTTsLzF", creds.getSecretKey());
        assertEquals("AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=", creds.getSessionToken().get());
    }

}
