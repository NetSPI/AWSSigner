package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FileProfileImporterTest {

    private final Path parentTestInputFolder = Paths.get("src", "test", "resources", "FileProfileImportInputs");

    @Test
    public void testSimpleSingleImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("default", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testSingleImportWithProfileName() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_profile_name.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("my-profile", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testSingleImportWithConfig() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_with_config.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("default", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testSingleImportWithIgnoredExtraProperties() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_with_ignored_extras.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("default", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testSingleImportWithSession() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_with_session.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("default", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertEquals("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4Olgk", staticCredentialsProfile.getSessionToken().get());
    }
    
    @Test
    public void testSingleImportMixedCase() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("single_simple_profile_test_mixed_case.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("default", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testMultipleImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("multiple_profile_test.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(2, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("profile1", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODAA7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());

        profile = importProfiles.get(1);
        assertTrue(profile instanceof StaticCredentialsProfile);
        staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("profile2", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODBB7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("BBalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());
    }

    @Test
    public void testAssumeRoleSingleImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("assume_role_profile_test.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(2, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("user1", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());

        profile = importProfiles.get(1);
        assertTrue(profile instanceof AssumeRoleProfile);
        AssumeRoleProfile assumeRoleCredentialsProfile = (AssumeRoleProfile) profile;
        assertEquals("marketingadmin", assumeRoleCredentialsProfile.getName());
        assertEquals(importProfiles.get(0), assumeRoleCredentialsProfile.getAssumerProfile().get());
        assertEquals("arn:aws:iam::123456789012:role/marketingadminrole", assumeRoleCredentialsProfile.getRoleArn().get());
        assertEquals(3600, assumeRoleCredentialsProfile.getDurationSeconds().get());
        assertEquals("123456", assumeRoleCredentialsProfile.getExternalId().get());
        assertEquals("Session_Maria_Garcia", assumeRoleCredentialsProfile.getSessionName().get());
        assertTrue(assumeRoleCredentialsProfile.getSessionPolicy().isEmpty());
    }

    @Test
    public void testNestedAssumeRoleImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("nested_assume_role_profile_test.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(4, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof StaticCredentialsProfile);
        StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) profile;
        assertEquals("static", staticCredentialsProfile.getName());
        assertEquals("AKIAIOSFODNN7EXAMPLE", staticCredentialsProfile.getAccessKey().get());
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", staticCredentialsProfile.getSecretKey().get());
        assertTrue(staticCredentialsProfile.getSessionToken().isEmpty());

        profile = importProfiles.get(1);
        assertTrue(profile instanceof AssumeRoleProfile);
        AssumeRoleProfile assumeRoleCredentialsProfile = (AssumeRoleProfile) profile;
        assertEquals("assume1", assumeRoleCredentialsProfile.getName());
        assertEquals(importProfiles.get(0), assumeRoleCredentialsProfile.getAssumerProfile().get());
        assertEquals("arn:aws:iam::123456789012:role/marketingadminrole", assumeRoleCredentialsProfile.getRoleArn().get());
        assertEquals(3600, assumeRoleCredentialsProfile.getDurationSeconds().get());
        assertEquals("123456", assumeRoleCredentialsProfile.getExternalId().get());
        assertEquals("Session_Maria_Garcia", assumeRoleCredentialsProfile.getSessionName().get());
        assertTrue(assumeRoleCredentialsProfile.getSessionPolicy().isEmpty());
        
        profile = importProfiles.get(2);
        assertTrue(profile instanceof AssumeRoleProfile);
        assumeRoleCredentialsProfile = (AssumeRoleProfile) profile;
        assertEquals("assume2", assumeRoleCredentialsProfile.getName());
        assertEquals(importProfiles.get(1), assumeRoleCredentialsProfile.getAssumerProfile().get());
        assertEquals("arn:aws:iam::123456789012:role/marketingadminrole", assumeRoleCredentialsProfile.getRoleArn().get());
        assertEquals(3600, assumeRoleCredentialsProfile.getDurationSeconds().get().intValue());
        assertEquals("123456", assumeRoleCredentialsProfile.getExternalId().get());
        assertEquals("Session_Maria_Garcia", assumeRoleCredentialsProfile.getSessionName().get());
        assertTrue(assumeRoleCredentialsProfile.getSessionPolicy().isEmpty());
        
        profile = importProfiles.get(3);
        assertTrue(profile instanceof AssumeRoleProfile);
         assumeRoleCredentialsProfile = (AssumeRoleProfile) profile;
        assertEquals("assume3", assumeRoleCredentialsProfile.getName());
        assertEquals(importProfiles.get(2), assumeRoleCredentialsProfile.getAssumerProfile().get());
        assertEquals("arn:aws:iam::123456789012:role/marketingadminrole", assumeRoleCredentialsProfile.getRoleArn().get());
        assertEquals(3600, assumeRoleCredentialsProfile.getDurationSeconds().get().intValue());
        assertEquals("123456", assumeRoleCredentialsProfile.getExternalId().get());
        assertEquals("Session_Maria_Garcia", assumeRoleCredentialsProfile.getSessionName().get());
        assertTrue(assumeRoleCredentialsProfile.getSessionPolicy().isEmpty());
    }

    @Test
    public void testExternalCommandImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("external_command_profile_test.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof CommandProfile);
        CommandProfile commandProfile = (CommandProfile) profile;
        assertEquals("developer", commandProfile.getName());
        assertTrue(commandProfile.getKeyId().isEmpty());
        assertEquals("/opt/bin/awscreds-custom --username helen", commandProfile.getCommand().get());
        assertEquals(3600, commandProfile.getDurationSeconds().get().intValue());

    }
    
    @Test
    public void testExternalCommandNoDurationImport() throws IOException {
        Path inputPath = parentTestInputFolder.resolve("external_command_profile_no_duration.txt");
        FileProfileImporter importer = new FileProfileImporter(inputPath);
        List<Profile> importProfiles = importer.importProfiles();
        assertEquals(1, importProfiles.size());

        Profile profile = importProfiles.get(0);
        assertTrue(profile instanceof CommandProfile);
        CommandProfile commandProfile = (CommandProfile) profile;
        assertEquals("developer", commandProfile.getName());
        assertTrue(commandProfile.getKeyId().isEmpty());
        assertEquals("/opt/bin/awscreds-custom --username helen", commandProfile.getCommand().get());
        assertTrue(commandProfile.getDurationSeconds().isEmpty());

    }

}
