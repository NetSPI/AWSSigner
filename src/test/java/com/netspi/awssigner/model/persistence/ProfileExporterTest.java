package com.netspi.awssigner.model.persistence;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public class ProfileExporterTest {

    private Path tempFile;
    private ProfileExporter exporter;

    @BeforeEach
    public void setUp() throws Exception {
        tempFile = Files.createTempFile("ProfileExporterTest", null);
        exporter = new ProfileExporter(tempFile);
    }

    @AfterEach
    public void tearDown() throws Exception {
        Files.deleteIfExists(tempFile);
    }

    @Test
    public void testStaticCreds() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        StaticCredentialsProfile exportProfile = new StaticCredentialsProfile("name");
        exportProfile.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        exportProfile.setSecretKey("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        exportProfiles.add(exportProfile);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        StaticCredentialsProfile importProfile = (StaticCredentialsProfile) importProfiles.get(0);
        assertEquals(exportProfile.getName(), importProfile.getName());
        assertEquals(exportProfile.getAccessKey().get(), importProfile.getAccessKey().get());
        assertEquals(exportProfile.getSecretKey().get(), importProfile.getSecretKey().get());
    }

    @Test
    public void testStaticCredsWithAllFields() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        StaticCredentialsProfile exportProfile = new StaticCredentialsProfile("name");
        exportProfile.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        exportProfile.setSecretKey("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        exportProfile.setSessionToken("AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=");
        exportProfile.setEnabled(false);
        exportProfile.setInScopeOnly(true);
        exportProfile.setKeyId("AKIAIOSFODNN8EXAMPLE");
        exportProfile.setRegion("us-west-2");
        exportProfile.setService("some-service");

        exportProfiles.add(exportProfile);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        StaticCredentialsProfile importProfile = (StaticCredentialsProfile) importProfiles.get(0);
        assertEquals(exportProfile.getName(), importProfile.getName());
        assertEquals(exportProfile.getAccessKey().get(), importProfile.getAccessKey().get());
        assertEquals(exportProfile.getSecretKey().get(), importProfile.getSecretKey().get());
        assertEquals(exportProfile.getSessionToken().get(), importProfile.getSessionToken().get());
        assertEquals(exportProfile.isEnabled(), importProfile.isEnabled());
        assertEquals(exportProfile.isInScopeOnly(), importProfile.isInScopeOnly());
        assertEquals(exportProfile.getKeyId().get(), importProfile.getKeyId().get());
        assertEquals(exportProfile.getRegion().get(), importProfile.getRegion().get());
        assertEquals(exportProfile.getService().get(), importProfile.getService().get());
    }

    @Test
    public void testCommandProfile() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        CommandProfile exportProfile = new CommandProfile("name");
        exportProfile.setCommand("/opt/bin/awscreds-custom --username will");

        exportProfiles.add(exportProfile);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        CommandProfile importProfile = (CommandProfile) importProfiles.get(0);
        assertEquals(exportProfile.getName(), importProfile.getName());
        assertEquals(exportProfile.getCommand().get(), importProfile.getCommand().get());
    }

    @Test
    public void testCommandProfileWithAllFields() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        CommandProfile exportProfile = new CommandProfile("name");
        exportProfile.setCommand("/opt/bin/awscreds-custom --username will");
        exportProfile.setDurationSeconds(10);
        exportProfile.setEnabled(false);
        exportProfile.setInScopeOnly(true);
        exportProfile.setKeyId("AKIAIOSFODNN8EXAMPLE");
        exportProfile.setRegion("us-west-2");
        exportProfile.setService("some-service");

        exportProfiles.add(exportProfile);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        CommandProfile importProfile = (CommandProfile) importProfiles.get(0);
        assertEquals(exportProfile.getName(), importProfile.getName());
        assertEquals(exportProfile.getCommand().get(), importProfile.getCommand().get());
        assertEquals(exportProfile.getDurationSeconds().get(), importProfile.getDurationSeconds().get());
        assertEquals(exportProfile.isEnabled(), importProfile.isEnabled());
        assertEquals(exportProfile.isInScopeOnly(), importProfile.isInScopeOnly());
        assertEquals(exportProfile.getKeyId().get(), importProfile.getKeyId().get());
        assertEquals(exportProfile.getRegion().get(), importProfile.getRegion().get());
        assertEquals(exportProfile.getService().get(), importProfile.getService().get());
    }

    @Test
    public void testAssumeProfile() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        StaticCredentialsProfile exportProfile1 = new StaticCredentialsProfile("name");
        exportProfile1.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        exportProfile1.setSecretKey("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        exportProfiles.add(exportProfile1);

        AssumeRoleProfile exportProfile2 = new AssumeRoleProfile("name2");
        exportProfile2.setAssumerProfile(exportProfile1);
        exportProfile2.setRoleArn("arn:aws:iam::123456789012:role/testrole");

        exportProfiles.add(exportProfile2);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        StaticCredentialsProfile importProfile1 = (StaticCredentialsProfile) importProfiles.get(0);
        assertEquals(exportProfile1.getName(), importProfile1.getName());
        assertEquals(exportProfile1.getAccessKey().get(), importProfile1.getAccessKey().get());
        assertEquals(exportProfile1.getSecretKey().get(), importProfile1.getSecretKey().get());

        AssumeRoleProfile importProfile2 = (AssumeRoleProfile) importProfiles.get(1);
        assertEquals(exportProfile2.getName(), importProfile2.getName());
        assertEquals(exportProfile2.getAssumerProfile().get(), importProfile2.getAssumerProfile().get());
        assertEquals(exportProfile2.getRoleArn().get(), importProfile2.getRoleArn().get());
    }

    @Test
    public void testAssumeProfileWithSessionPolicyWithLineBreaks() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        StaticCredentialsProfile exportProfile1 = new StaticCredentialsProfile("name");
        exportProfile1.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        exportProfile1.setSecretKey("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        exportProfiles.add(exportProfile1);

        AssumeRoleProfile exportProfile2 = new AssumeRoleProfile("name2");
        exportProfile2.setAssumerProfile(exportProfile1);
        exportProfile2.setRoleArn("arn:aws:iam::123456789012:role/testrole");

        //Set some complex session policy
        String sessionPolicy = "{    \"Version\": \"2012-10-17\",    \"Statement\": [        {            \"Sid\": \"AllowListingOfUserFolder\",            \"Action\": [                \"s3:ListBucket\"            ],            \"Effect\": \"Allow\",            \"Resource\": [                \"arn:aws:s3:::${transfer:HomeBucket}\"            ],            \"Condition\": {                \"StringLike\": {                    \"s3:prefix\": [                        \"${transfer:HomeFolder}/*\",                        \"${transfer:HomeFolder}\"                    ]                }            }        },        {            \"Sid\": \"HomeDirObjectAccess\",            \"Effect\": \"Allow\",            \"Action\": [                \"s3:PutObject\",                \"s3:GetObject\",                \"s3:DeleteObject\",                \"s3:DeleteObjectVersion\",                \"s3:GetObjectVersion\",                \"s3:GetObjectACL\",                \"s3:PutObjectACL\"            ],            \"Resource\": \"arn:aws:s3:::${transfer:HomeDirectory}*\"        }    ]}     ";
        //Parse the session policy text into JSON
        JsonObject json = JsonParser.parseString(sessionPolicy).getAsJsonObject();
        //Back to a string with pretty-printing
        String prettyJson = new GsonBuilder().setPrettyPrinting().create().toJson(json);
        exportProfile2.setSessionPolicy(prettyJson);

        exportProfiles.add(exportProfile2);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        StaticCredentialsProfile importProfile1 = (StaticCredentialsProfile) importProfiles.get(0);
        assertEquals(exportProfile1.getName(), importProfile1.getName());
        assertEquals(exportProfile1.getAccessKey().get(), importProfile1.getAccessKey().get());
        assertEquals(exportProfile1.getSecretKey().get(), importProfile1.getSecretKey().get());

        AssumeRoleProfile importProfile2 = (AssumeRoleProfile) importProfiles.get(1);
        assertEquals(exportProfile2.getName(), importProfile2.getName());
        assertEquals(exportProfile2.getAssumerProfile().get(), importProfile2.getAssumerProfile().get());
        assertEquals(exportProfile2.getRoleArn().get(), importProfile2.getRoleArn().get());
        
        //Is the session policy stil the same (ignoring whitespace)?
        assertEquals(sessionPolicy.replaceAll("\\s+", " ").trim(), importProfile2.getSessionPolicy().get().replaceAll("\\s+", " ").trim());
    }

    @Test
    public void testAssumeProfileWithAllFields() throws Exception {
        List<Profile> exportProfiles = new ArrayList<>();

        StaticCredentialsProfile exportProfile1 = new StaticCredentialsProfile("name");
        exportProfile1.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        exportProfile1.setSecretKey("AAalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        exportProfiles.add(exportProfile1);

        AssumeRoleProfile exportProfile2 = new AssumeRoleProfile("name2");
        exportProfile2.setAssumerProfile(exportProfile1);
        exportProfile2.setRoleArn("arn:aws:iam::123456789012:role/testrole");
        exportProfile2.setExternalId("some_ext_id");
        exportProfile2.setSessionName("my_session_name");
        exportProfile2.setSessionPolicy("{    \"Version\": \"2012-10-17\",    \"Statement\": [        {            \"Sid\": \"AllowListingOfUserFolder\",            \"Action\": [                \"s3:ListBucket\"            ],            \"Effect\": \"Allow\",            \"Resource\": [                \"arn:aws:s3:::${transfer:HomeBucket}\"            ],            \"Condition\": {                \"StringLike\": {                    \"s3:prefix\": [                        \"${transfer:HomeFolder}/*\",                        \"${transfer:HomeFolder}\"                    ]                }            }        },        {            \"Sid\": \"HomeDirObjectAccess\",            \"Effect\": \"Allow\",            \"Action\": [                \"s3:PutObject\",                \"s3:GetObject\",                \"s3:DeleteObject\",                \"s3:DeleteObjectVersion\",                \"s3:GetObjectVersion\",                \"s3:GetObjectACL\",                \"s3:PutObjectACL\"            ],            \"Resource\": \"arn:aws:s3:::${transfer:HomeDirectory}*\"        }    ]}     ");
        exportProfile2.setDurationSeconds(10);
        exportProfile2.setEnabled(false);
        exportProfile2.setInScopeOnly(true);
        exportProfile2.setKeyId("AKIAIOSFODNN8EXAMPLE");
        exportProfile2.setRegion("us-west-2");
        exportProfile2.setService("some-service");

        exportProfiles.add(exportProfile2);

        exporter.exportProfiles(exportProfiles);

        FileProfileImporter importer = new FileProfileImporter(tempFile);
        List<Profile> importProfiles = importer.importProfiles();

        assertEquals(exportProfiles.size(), importProfiles.size());

        StaticCredentialsProfile importProfile1 = (StaticCredentialsProfile) importProfiles.get(0);
        assertEquals(exportProfile1.getName(), importProfile1.getName());
        assertEquals(exportProfile1.getAccessKey().get(), importProfile1.getAccessKey().get());
        assertEquals(exportProfile1.getSecretKey().get(), importProfile1.getSecretKey().get());

        AssumeRoleProfile importProfile2 = (AssumeRoleProfile) importProfiles.get(1);
        assertEquals(exportProfile2.getName(), importProfile2.getName());
        assertEquals(exportProfile2.getAssumerProfile().get(), importProfile2.getAssumerProfile().get());
        assertEquals(exportProfile2.getRoleArn().get(), importProfile2.getRoleArn().get());
        assertEquals(exportProfile2.getDurationSeconds().get(), importProfile2.getDurationSeconds().get());
        assertEquals(exportProfile2.getExternalId().get(), importProfile2.getExternalId().get());
        assertEquals(exportProfile2.getSessionName().get(), importProfile2.getSessionName().get());
        assertEquals(exportProfile2.getSessionPolicy().get().replaceAll("\\s+", " ").trim(), importProfile2.getSessionPolicy().get().replaceAll("\\s+", " ").trim());
        assertEquals(exportProfile2.isEnabled(), importProfile2.isEnabled());
        assertEquals(exportProfile2.isInScopeOnly(), importProfile2.isInScopeOnly());
        assertEquals(exportProfile2.getKeyId().get(), importProfile2.getKeyId().get());
        assertEquals(exportProfile2.getRegion().get(), importProfile2.getRegion().get());
        assertEquals(exportProfile2.getService().get(), importProfile2.getService().get());
    }

}
