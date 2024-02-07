package com.netspi.awssigner.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.netspi.awssigner.utils.AWSSignerUtils;

import burp.IBurpExtenderCallbacks;

public class AWSSignerConfiguration implements Serializable {
    public volatile boolean isEnabled =  true;
    public volatile List<Profile> profiles = new ArrayList<>();
    public volatile Profile alwaysSignWithProfile;
    public volatile int signForTools = IBurpExtenderCallbacks.TOOL_SUITE;
    public volatile boolean shouldPersist = true;

    public static final String STORED_CONFIG_OBJECT_KEY = "aws-signer-configuration";

    public synchronized void persist() {
        if (shouldPersist) {
            AWSSignerUtils.storeObjectForCurrentProject(STORED_CONFIG_OBJECT_KEY, this);
        }
    }

    public static AWSSignerConfiguration getOrCreateProjectConfiguration() {

        AWSSignerConfiguration config = new AWSSignerConfiguration();

        Object o = AWSSignerUtils.getStoredObjectForCurrentProject(STORED_CONFIG_OBJECT_KEY);

        if ( o != null && o instanceof AWSSignerConfiguration) {
            config = (AWSSignerConfiguration) o;
        }

        return config;
    }

    public List<String> getProfileNames() {
        return profiles.stream().map(Profile::getName).collect(Collectors.toList());
    }
    
    /**
     * Gets the profile, if it exists. 
     * @param name The name of the profile to get
     * @return The profile, if it exists
     */
    public Optional<Profile> getProfileForName(String name){
        if(name == null || name.isEmpty()){
            return Optional.empty();
        }
        return profiles.stream().filter(profile -> profile.getName().equals(name)).findFirst();
    }
    
}
