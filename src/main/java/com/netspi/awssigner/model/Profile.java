package com.netspi.awssigner.model;

import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;

import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;

public abstract class Profile implements Serializable {

    protected String name;
    protected boolean isEnabled = true;
    protected boolean inScopeOnly = false;
    protected String region = null;
    protected String service = null;
    protected String keyId = null;

    public Profile(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("The Profile name may not be null or blank.");
        }
        this.name = name;
    }

    /**
     * Must be set, will not be null or blank.
     */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("The Profile name may not be null or blank.");
        }
        this.name = name;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    public boolean isInScopeOnly() {
        return inScopeOnly;
    }

    public void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getRegion() {
        return Optional.ofNullable(region);
    }

    public void setRegion(String region) {
        if (region != null && region.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.region = null;
        } else {
            this.region = region;
        }
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getService() {
        return Optional.ofNullable(service);
    }

    public void setService(String service) {
        if (service != null && service.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.service = null;
        } else {
            this.service = service;
        }
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getKeyId() {
        return Optional.ofNullable(keyId);
    }

    public void setKeyId(String keyId) {
        if (keyId != null && keyId.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.keyId = null;
        } else {
            this.keyId = keyId;
        }
    }

    /**
     * Returns true if the required fields for the profile are set but does not
     * confirm if those set values are themselves valid.
     *
     * @return true if the profile's required fields are set, false otherwise.
     */
    public abstract boolean requiredFieldsAreSet();

    @Override
    public int hashCode() {
        return Objects.hashCode(this.name);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Profile other = (Profile) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "{" + "name=" + name + ", isEnabled=" + isEnabled + ", inScopeOnly=" + inScopeOnly + ", region=" + region + ", service=" + service + ", keyId=" + keyId + '}';
    }

    public abstract SigningCredentials getCredentials() throws SignerCredentialException;

}
