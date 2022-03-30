package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class EnvironmentVariableProfileImporter implements ProfileImporter {

    @Override
    public List<Profile> importProfiles() {
        List<Profile> profiles = new ArrayList<>(1);

        //ignore case for keys
        Map<String, String> env = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        //Add all the current environment variables
        env.putAll(System.getenv());

        //Pull out environment variables
        String accessKey = env.get("AWS_ACCESS_KEY_ID");
        String secretKey = env.get("AWS_SECRET_ACCESS_KEY");
        String sessionToken = env.get("AWS_SESSION_TOKEN");

        //Check if we have the required 2
        if (accessKey != null && !accessKey.isEmpty() && secretKey != null && !secretKey.isEmpty()) {
            StaticCredentialsProfile profile = new StaticCredentialsProfile("environment_variables");
            profile.setAccessKey(accessKey);
            profile.setSecretKey(secretKey);
            //Check if we have a session token too
            if (sessionToken != null && !sessionToken.isEmpty()) {
                profile.setSessionToken(sessionToken);
            }
            profiles.add(profile);
        }

        return profiles;
    }

}
