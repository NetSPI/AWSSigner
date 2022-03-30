package com.netspi.awssigner.model.persistence;

import static com.netspi.awssigner.log.LogWriter.logError;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import static com.netspi.awssigner.model.persistence.ProfileFileKeyConstants.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class ProfileExporter {


    private final Path exportPath;

    public ProfileExporter(Path exportPath) {
        this.exportPath = exportPath;
    }

    public void exportProfiles(List<Profile> profiles) throws IOException {
        List<String> iniProfiles = profiles.stream()
                .map(this::toINI)
                .filter(iniString -> {
                    return iniString != null && !iniString.trim().isEmpty();
                })
                .collect(Collectors.toList());

        Files.write(exportPath, iniProfiles, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }

    private String toINI(Profile profile) {
        if (profile == null || !profile.requiredFieldsAreSet()) {
            return "";
        }
        
        String profileFields = getProfileFields(profile);
        
        //Handle type-specific status transformation
        if (profile instanceof StaticCredentialsProfile) {
            return profileFields+getStaticCredsFields((StaticCredentialsProfile) profile);
        } else if (profile instanceof AssumeRoleProfile) {
            return profileFields+getAssumeRoleFields((AssumeRoleProfile) profile);
        } else if (profile instanceof CommandProfile) {
            return profileFields+getCommandFields((CommandProfile) profile);
        } else {
            final String errorMessage = "Profile does not match expected type. Found Type: " + profile.getClass().getName();
            logError(errorMessage);
            return "";
        }
    }

    private String getProfileFields(Profile profile) {
        //Start the profile output
        String result = "[profile " + profile.getName() + "]" + System.lineSeparator();
        
        //Output required fields
        result += requiredKeyValueBoolean(PROFILE_ENABLED_KEY, profile.isEnabled());
        result += requiredKeyValueBoolean(PROFILE_IN_SCOPE_ONLY_KEY, profile.isInScopeOnly());
        

        //Output optional generic Profile fields
        result += optionalKeyValueString(PROFILE_KEY_ID_KEY, profile.getKeyId());
        result += optionalKeyValueString(PROFILE_REGION_KEY, profile.getRegion());
        result += optionalKeyValueString(PROFILE_SERVICE_KEY, profile.getService());
        return result;
    }


    private String getStaticCredsFields(StaticCredentialsProfile profile) {
        String result = "";

        //Check if we have the minimum requirements
        if (profile.requiredFieldsAreSet()) {
            //Output type-specific required fields
            result += requiredKeyValueString(STATIC_CREDS_ACCESS_KEY_KEY, profile.getAccessKey());
            result += requiredKeyValueString(STATIC_CREDS_SECRET_KEY_KEY, profile.getSecretKey());

            //Output type-specific optional fields
            result += optionalKeyValueString(STATIC_CREDS_SESSION_TOKEN_KEY, profile.getSessionToken());
        }

        return result;
    }
    
    
    private String getAssumeRoleFields(AssumeRoleProfile profile) {
        String result = "";

        //Check if we have the minimum requirements
        if (profile.requiredFieldsAreSet()) {
            //Output type-specific required fields
            result += requiredKeyValueString(ASSUME_ROLE_ROLE_ARN_KEY, profile.getRoleArn());
            result += requiredKeyValueString(ASSUME_ROLE_ASSUMER_PROFILE_NAME_KEY, Optional.of(profile.getAssumerProfile().get().getName()));

            //Output type-specific optional fields
            result += optionalKeyValueString(DURATION_SECONDS_KEY, profile.getDurationSeconds());
            result += optionalKeyValueString(ASSUME_ROLE_EXTERNAL_ID_KEY, profile.getExternalId());
            result += optionalKeyValueString(ASSUME_ROLE_SESSION_NAME_KEY, profile.getSessionName());
            if(profile.getSessionPolicy().isPresent()){
                String sessionPolicy = profile.getSessionPolicy().get();
                //output must be a single line. Strip line breaks
                sessionPolicy = sessionPolicy.replace("\n", "").replace("\r", "").trim();
                result += optionalKeyValueString(ASSUME_ROLE_SESSION_POLICY_KEY, Optional.of(sessionPolicy));
            }
        }

        return result;
    }
    
    
    private String getCommandFields(CommandProfile profile) {
        String result = "";

        //Check if we have the minimum requirements
        if (profile.requiredFieldsAreSet()) {
            //Output type-specific required fields
            result += requiredKeyValueString(COMMAND_COMMAND_KEY, profile.getCommand());

            //Output type-specific optional fields
            result += optionalKeyValueString(DURATION_SECONDS_KEY, profile.getDurationSeconds());
        }

        return result;
    }


    private String requiredKeyValueBoolean(String key, boolean value) {
        return key + "=" + Boolean.toString(value) + System.lineSeparator();
    }
    
    private String requiredKeyValueString(String key, Optional value) {
        return key + "=" + value.get().toString() + System.lineSeparator();
    }

    private String optionalKeyValueString(String key, Optional value) {
        if (value.isPresent()) {
            return key + "=" + value.get().toString() + System.lineSeparator();
        } else {
            return "";
        }
    }

}
