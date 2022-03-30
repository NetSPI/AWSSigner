package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import static com.netspi.awssigner.model.persistence.ProfileFileKeyConstants.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.Collectors;

public class FileProfileImporter implements ProfileImporter {

    private static final Pattern awsProfileStartPattern = Pattern.compile("\\s*\\[(?:profile\\s)?(\\S+)\\]\\s*", Pattern.CASE_INSENSITIVE);
    private static final int PROFILE_NAME_GROUP = 1;
    private static final Pattern awsProfileKVPattern = Pattern.compile("\\s*([\\S\\=]+)\\s*=\\s*(.+)\\s*", Pattern.CASE_INSENSITIVE);
    private static final int KEY_GROUP = 1;
    private static final int VALUE_GROUP = 2;
    private final Path inputPath;

    public FileProfileImporter(Path inputPath) {
        this.inputPath = inputPath;
    }

    @Override
    public List<Profile> importProfiles() {
        //Read all the profiles available in the input file. These are basically raw KV pairs. 
        List<PersistedProfile> parsedProfiles = parseProfilesFromPath(inputPath);
        return parseAndConvertProfiles(parsedProfiles);
        
    }
    
    static List<Profile> parseAndConvertProfiles(List<PersistedProfile> parsedProfiles) {
        List<Profile> profiles = new ArrayList<>();
        //The following section needs to convert the parsed profiles into real Profiles. 
        //For StaticCreds and Command profiles, this is easy one-to-one mapping. 
        //For AssumeRole profile, we need to reference the previously imported source profile which really makes this more complex
        //Let's start by importing all the simple ones (Static and Command)
        for (Iterator<PersistedProfile> iterator = parsedProfiles.iterator(); iterator.hasNext();) {
            PersistedProfile parsedProfile = iterator.next();
            final Map<String, String> keyValuePairs = parsedProfile.keyValuePairs;

            //Need to identify which type of profile we have. 
            if (keyValuePairs.containsKey(STATIC_CREDS_ACCESS_KEY_KEY) && keyValuePairs.containsKey(STATIC_CREDS_SECRET_KEY_KEY)) {
                //We have minimum requirements for StaticCreds profile
                StaticCredentialsProfile staticCredsProfile = new StaticCredentialsProfile(parsedProfile.name);
                String accessKey = keyValuePairs.get(STATIC_CREDS_ACCESS_KEY_KEY);
                staticCredsProfile.setAccessKey(accessKey);

                String secretKey = keyValuePairs.get(STATIC_CREDS_SECRET_KEY_KEY);
                staticCredsProfile.setSecretKey(secretKey);

                String sessionToken = keyValuePairs.get(STATIC_CREDS_SESSION_TOKEN_KEY);
                staticCredsProfile.setSessionToken(sessionToken);
                
                addGenericProfileVales(staticCredsProfile, keyValuePairs);
                
                //add to profiles list and remove from parsed profiles
                profiles.add(staticCredsProfile);
                iterator.remove();

            } else if (keyValuePairs.containsKey(COMMAND_COMMAND_KEY)) {
                //We have minimum requirements for Command  profile
                CommandProfile commandProfile = new CommandProfile(parsedProfile.name);
                String command = keyValuePairs.get(COMMAND_COMMAND_KEY);
                commandProfile.setCommand(command);

                String durationString = keyValuePairs.get(DURATION_SECONDS_KEY);
                commandProfile.setDurationSecondsFromText(durationString);
                
                addGenericProfileVales(commandProfile, keyValuePairs);

                //add to profiles list and remove from parsed profiles
                profiles.add(commandProfile);
                iterator.remove();
            }
            //if it didn't meet those, ignore and loop 
        }

        //Now that we have the simple ones, the ones remaining are either AssumeRole profiles (or a profile we can't properly import)
        //We need to keep attempting to parse assume role profiles until we stop making progress.
        int processedProfiles;
        do {
            processedProfiles = 0;
            for (Iterator<PersistedProfile> iterator = parsedProfiles.iterator(); iterator.hasNext();) {
                PersistedProfile parsedProfile = iterator.next();
                final Map<String, String> keyValuePairs = parsedProfile.keyValuePairs;
                if (keyValuePairs.containsKey(ASSUME_ROLE_ROLE_ARN_KEY) && keyValuePairs.containsKey(ASSUME_ROLE_ASSUMER_PROFILE_NAME_KEY)) {
                    //We have minimum requirements for AssumeRole profile

                    //Check if we've already parsed its source profile
                    String sourceProfileName = keyValuePairs.get(ASSUME_ROLE_ASSUMER_PROFILE_NAME_KEY);
                    Optional<Profile> sourceProfileOptional = profiles.stream().filter(profile -> {
                        return profile.getName().equals(sourceProfileName);
                    }).findAny();
                    if (sourceProfileOptional.isEmpty()) {
                        //We haven't found the source yet. Ignore this parsed profile and continue
                        continue;
                    }

                    AssumeRoleProfile assumeRoleProfile = new AssumeRoleProfile(parsedProfile.name);
                    assumeRoleProfile.setAssumerProfile(sourceProfileOptional.get());

                    String roleARN = keyValuePairs.get(ASSUME_ROLE_ROLE_ARN_KEY);
                    assumeRoleProfile.setRoleArn(roleARN);

                    String durationString = keyValuePairs.get(DURATION_SECONDS_KEY);
                    assumeRoleProfile.setDurationSecondsFromText(durationString);

                    String externalId = keyValuePairs.get(ASSUME_ROLE_EXTERNAL_ID_KEY);
                    assumeRoleProfile.setExternalId(externalId);

                    String roleSessionName = keyValuePairs.get(ASSUME_ROLE_SESSION_NAME_KEY);
                    assumeRoleProfile.setSessionName(roleSessionName);
                    
                    String roleSessionPolicy = keyValuePairs.get(ASSUME_ROLE_SESSION_POLICY_KEY);
                    assumeRoleProfile.setSessionPolicy(roleSessionPolicy);
                    
                    addGenericProfileVales(assumeRoleProfile, keyValuePairs);

                    //add to profiles list and remove from parsed profiles
                    profiles.add(assumeRoleProfile);
                    iterator.remove();
                    processedProfiles++;
                }
            }
        } while (!parsedProfiles.isEmpty() && processedProfiles > 0);

        //We're all done. Let's output a warning if there's any remaining. 
        if (!parsedProfiles.isEmpty()) {
            //Get a list of profile names we couldn't parse
            List<String> unparsableNames = parsedProfiles.stream().map(profile -> profile.name).collect(Collectors.toList());
            LogWriter.logError("Unable to parse the following profiles: " + unparsableNames);
        }

        return profiles;
    }

    //We're collecting all ParsedProfiles from the given input file
    //The input file is assumed to be in the AWS config/creds file format
    List<PersistedProfile> parseProfilesFromPath(Path inputPath) {
        List<PersistedProfile> profiles = new ArrayList<>();

        //This is goofy, this should be cleaned up.
        try ( Stream<String> lineStream = Files.lines(inputPath)) {
            String profileName = null;
            HashMap<String, String> keyValuePairs = new HashMap<>();

            for (Iterator<String> iterator = lineStream.iterator(); iterator.hasNext();) {
                String line = iterator.next();
                //Check if it's the start of a profile definition
                Matcher profileStartMatcher = awsProfileStartPattern.matcher(line);
                if (profileStartMatcher.matches()) {
                    //This is the start of a new profile

                    //Check if we've already found a profile name
                    if (profileName != null) {
                        //This must be the start of another profile. 
                        mergePersistedProfile(profiles, profileName, keyValuePairs);
                    }
                    //Capture the profile name
                    profileName = profileStartMatcher.group(PROFILE_NAME_GROUP);
                    //clear previous key values
                    keyValuePairs = new HashMap<>();
                }

                //Didn't match a profile start. Is it a key-value pair?
                Matcher kvMatcher = awsProfileKVPattern.matcher(line);
                if (kvMatcher.matches()) {
                    //Add it to our map of key-value pairs
                    keyValuePairs.put(kvMatcher.group(KEY_GROUP), kvMatcher.group(VALUE_GROUP));
                }
            }

            //This should be the end of the file. Save any profile that was in being parsed
            if (profileName != null) {
                //This must be the start of another profile. 
                mergePersistedProfile(profiles, profileName, keyValuePairs);
            }
        } catch (IOException err) {
            LogWriter.logError("Unable to load profiles from path: " + inputPath.toString() + " . Error: " + err.toString());
        }
        return profiles;
    }

    void mergePersistedProfile(List<PersistedProfile> profiles, String profileName, Map<String, String> keyValuePairs) {
        //Check our growing list of parsed profiles to see if we have already found one with the same name. 
        Optional<PersistedProfile> existingProfileOptional = profiles.stream().filter(profile -> {
            return profile.name.equals(profileName);
        }).findAny();

        if (existingProfileOptional.isPresent()) {
            //Since we have previously found a profile with the same name. Merge these
            PersistedProfile existingProfile = existingProfileOptional.get();
            existingProfile.keyValuePairs.putAll(keyValuePairs);
        } else {
            //Build and save the previous profile.
            profiles.add(new PersistedProfile(profileName, keyValuePairs));
        }
    }

    private static void addGenericProfileVales(Profile profile, Map<String, String> keyValuePairs) {
       //special handling for the boolean values (if present)
       if(keyValuePairs.containsKey(PROFILE_ENABLED_KEY)){
           String enabledStringValue = keyValuePairs.get(PROFILE_ENABLED_KEY);
           profile.setEnabled(Boolean.parseBoolean(enabledStringValue));
       }
       if(keyValuePairs.containsKey(PROFILE_IN_SCOPE_ONLY_KEY)){
           String inScopeOnlyStringValue = keyValuePairs.get(PROFILE_IN_SCOPE_ONLY_KEY);
           profile.setInScopeOnly(Boolean.parseBoolean(inScopeOnlyStringValue));
       }
       
       profile.setService(keyValuePairs.get(PROFILE_SERVICE_KEY));
       profile.setRegion(keyValuePairs.get(PROFILE_REGION_KEY));
       profile.setKeyId(keyValuePairs.get(PROFILE_KEY_ID_KEY));
    }

}
