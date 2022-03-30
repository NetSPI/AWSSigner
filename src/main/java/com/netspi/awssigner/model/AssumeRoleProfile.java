package com.netspi.awssigner.model;

import com.netspi.awssigner.credentials.AssumeRoleCredentialFetcher;
import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;
import java.util.Optional;

public class AssumeRoleProfile extends AbstractCachingProfile {

    private Profile assumerProfile;
    private String roleArn;
    private String sessionName;
    private String externalId;
    private String sessionPolicy;

    public AssumeRoleProfile(String name) {
        super(name);
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null Profile.
     */
    public Optional<Profile> getAssumerProfile() {
        return Optional.ofNullable(assumerProfile);
    }

    public void setAssumerProfile(Profile assumerProfile) {
        this.assumerProfile = assumerProfile;
        clearCache();
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getRoleArn() {
        return Optional.ofNullable(roleArn);
    }

    public void setRoleArn(String roleArn) {
        if (roleArn != null && roleArn.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.roleArn = null;
        } else {
            this.roleArn = roleArn;
        }
        clearCache();
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getSessionName() {
        return Optional.ofNullable(sessionName);
    }

    public void setSessionName(String sessionName) {
        if (sessionName != null && sessionName.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.sessionName = null;
        } else {
            this.sessionName = sessionName;
        }
        clearCache();
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getExternalId() {
        return Optional.ofNullable(externalId);
    }

    public void setExternalId(String externalId) {
        if (externalId != null && externalId.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.externalId = null;
        } else {
            this.externalId = externalId;
        }
        clearCache();
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getSessionPolicy() {
        return Optional.ofNullable(sessionPolicy);
    }

    public void setSessionPolicy(String sessionPolicy) {
        if (sessionPolicy != null && sessionPolicy.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.sessionPolicy = null;
        } else {
            this.sessionPolicy = sessionPolicy;
        }
        clearCache();
    }

    @Override
    public boolean requiredFieldsAreSet() {
        return roleArn != null && assumerProfile != null && !assumerProfile.getName().isEmpty();
    }

    @Override
    protected SigningCredentials getCredentialsNoCache() throws SignerCredentialException {
        if (assumerProfile == null && roleArn == null) {
            throw new SignerCredentialException("Assumer profile and role ARN are not set for profile: " + getName());
        } else if (assumerProfile == null) {
            throw new SignerCredentialException("Assumer profile is not set for profile: " + getName());
        } else if (roleArn == null) {
            throw new SignerCredentialException("Role ARN is not set for profile: " + getName());
        }
        AssumeRoleCredentialFetcher fetcher = new AssumeRoleCredentialFetcher(this);
        return fetcher.getCredentials();
    }
    
    

}
