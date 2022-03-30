package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.model.Profile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class AutoProfileImporter implements ProfileImporter{

   
    //Profiles could be defined in many default locations. Check each and keep those that exist. 
    private List<Path> getDefaultProfilePaths() {
        List<Path> profileFilePaths = new ArrayList<>();

        //AWS_CONFIG_FILE environment variable
        String envConfigFile = System.getenv("AWS_SHARED_CREDENTIALS_FILE");
        if (envConfigFile != null) {
            Path envPath = Paths.get(envConfigFile);
            if (Files.exists(envPath)) {
                profileFilePaths.add(envPath);
            }
        }

        //~/.aws/config
        Path configPath = Paths.get(System.getProperty("user.home"), ".aws", "config");
        if (Files.exists(configPath)) {
            profileFilePaths.add(configPath);
        }

        //AWS_SHARED_CREDENTIALS_FILE environment variable
        String envCredsFile = System.getenv("AWS_SHARED_CREDENTIALS_FILE");
        if (envCredsFile != null) {
            Path envPath = Paths.get(envCredsFile);
            if (Files.exists(envPath)) {
                profileFilePaths.add(envPath);
            }
        }

        //~/.aws/credentials
        Path credsPath = Paths.get(System.getProperty("user.home"), ".aws", "credentials");
        if (Files.exists(credsPath)) {
            profileFilePaths.add(credsPath);
        }

        return profileFilePaths;
    }

    public List<Profile> importProfiles() {
        //This basically steals logic from the different importer types

        //Import from default files
        List<Path> defaultPaths = getDefaultProfilePaths();
        List<PersistedProfile> filePersistentProfiles = new ArrayList<>();
        for (Path path : defaultPaths) {
            FileProfileImporter fileProfileImporter = new FileProfileImporter(path);
            List<PersistedProfile> parseProfilesFromPath = fileProfileImporter.parseProfilesFromPath(path);
            for (PersistedProfile persistedProfile : parseProfilesFromPath) {
                fileProfileImporter.mergePersistedProfile(filePersistentProfiles, persistedProfile.name, persistedProfile.keyValuePairs);
            }
        }
        List<Profile> profiles = FileProfileImporter.parseAndConvertProfiles(filePersistentProfiles);
        
        EnvironmentVariableProfileImporter envProfileImporter = new EnvironmentVariableProfileImporter();
        List<Profile> envProfiles = envProfileImporter.importProfiles();
        profiles.addAll(envProfiles);
        
        ClipboardProfileImporter clipboardProfileImporter = new ClipboardProfileImporter();
        List<Profile> clipboard = clipboardProfileImporter.importProfiles();
        profiles.addAll(clipboard);
        return profiles;
    }

   

   
}


