package com.netspi.awssigner.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;

public class AWSSignerConfiguration {
    public volatile boolean isEnabled =  true;
    public volatile List<Profile> profiles = new ArrayList<>();
    public volatile Profile alwaysSignWithProfile;
    public volatile int signForTools = IBurpExtenderCallbacks.TOOL_SUITE;

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
