package com.netspi.awssigner.model;

import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.netspi.awssigner.log.LogWriter;
import java.util.Optional;

public abstract class AbstractCachingProfile extends Profile {

    /**
     * Default lifetime of cached creds Using default value for assume role
     * command
     * https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html
     */
    private final static int DEFAULT_DURATION_SECONDS = 3600;

    /**
     * How long the cached credentials should be considered valid. A negative
     * value indicates that the duration seconds value has not been set for this
     * profile. If the value has not been set, the default value should be used
     * for determining the lifetime of the cached creds If the value has been
     * set, the value of durationSeconds should be used.
     */
    private volatile int durationSeconds = -1;

    /*
     * -1 means no creds have been cached and should be refetched
     */
    private volatile long expirationSeconds = -1;
    private volatile SigningCredentials cachedCreds;

    public AbstractCachingProfile(String name) {
        super(name);
    }

    /**
     * Empty Optional if no value has been set for the profile, otherwise the
     * set value.
     *
     * @return Empty Optional if no value has been set for the profile,
     * otherwise the set value.
     */
    public Optional<Integer> getDurationSeconds() {
        if (durationSeconds >= 0) {
            return Optional.of(durationSeconds);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Sets the duration (in seconds) for how long the cached credentials will
     * be considered valid. A null or negative input value unsets the value for
     * this profile and the default caching duration will be used. A non-null,
     * non-negative value sets the new duration.
     *
     * @param durationSeconds null/negative if the value should be unset (and
     * the default cache lifetime will be used will be used) or the value to be
     * used.
     */
    public void setDurationSeconds(Integer durationSeconds) {
        //Check for null/negative value
        if (durationSeconds == null || durationSeconds < 0) {
            this.durationSeconds = -1;
        } else {
            this.durationSeconds = durationSeconds;
        }
        clearCache();
    }

    /**
     * Sets the duration (in seconds) for how long the cached credentials will
     * be considered valid. A null or negative input value unsets the value for
     * this profile and the default caching duration will be used. A non-null,
     * non-negative value sets the new duration.
     *
     * @param durationSeconds null/negative if the value should be unset (and
     * the default cache lifetime will be used will be used) or the value to be
     * used.
     */
    public void setDurationSecondsFromText(String durationSeconds) {
        if (durationSeconds == null) {
            setDurationSeconds(null);
        }
        try {
            int duration = Integer.parseInt(durationSeconds);
            setDurationSeconds(duration);
        } catch (NumberFormatException e) {
            LogWriter.logDebug("Invalid input string provided for Profile Duration: " + durationSeconds + " using default of " + DEFAULT_DURATION_SECONDS + " seconds instead.");
            setDurationSeconds(null);
        }
    }

    @Override
    public SigningCredentials getCredentials() throws SignerCredentialException  {
        if(durationSeconds==0){
            LogWriter.logDebug("Duration set to zero. Fetching new credentials and not caching.");
            return getCredentialsNoCache();
        }
        
        long seconds = expirationSeconds;
        long now = System.currentTimeMillis() / 1000;
        if (seconds == -1 || now - seconds >= 0) {
            synchronized (this) {
                if (seconds == expirationSeconds) { // recheck for lost race
                    LogWriter.logDebug("Cache expired. Fetching new creds");
                    cachedCreds = getCredentialsNoCache();
                    if (durationSeconds >= 0) {
                       seconds = now + durationSeconds;
                    } else {
                       seconds = now + DEFAULT_DURATION_SECONDS;
                    }
                    expirationSeconds = seconds;
                }
            }
        }
        LogWriter.logDebug("Returning previously cached creds.");
        return cachedCreds;
    }
    
    protected void clearCache(){
        LogWriter.logDebug("Clearing the cache.");
        expirationSeconds = -1;
    }

    abstract protected SigningCredentials getCredentialsNoCache() throws SignerCredentialException ;

}
