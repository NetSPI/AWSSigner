package com.netspi.awssigner.credentials;

import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.Profile;
import java.util.Optional;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

public class AssumeRoleCredentialFetcher implements CredentialFetcher {

    private final AssumeRoleProfile profile;

    public AssumeRoleCredentialFetcher(AssumeRoleProfile profile) {
        this.profile = profile;
    }

    @Override
    public SigningCredentials getCredentials() throws SignerCredentialException {
        final Optional<String> roleArnOptional = profile.getRoleArn();
        final Optional<Profile> assumerProfileOptional = profile.getAssumerProfile();
        if (assumerProfileOptional.isEmpty() && roleArnOptional.isEmpty()) {
            throw new SignerCredentialException("Assumer profile and role ARN are not set for profile: " + profile.getName());
        } else if (assumerProfileOptional.isEmpty()) {
            throw new SignerCredentialException("Assumer profile is not set for profile: " + profile.getName());
        } else if (roleArnOptional.isEmpty()) {
            throw new SignerCredentialException("Role ARN is not set for profile: " + profile.getName());
        }

        try {
            Profile parentProfile = assumerProfileOptional.get();
            LogWriter.logDebug("Obtaining credentials to use when assuming role from parent assumer: " + parentProfile.getName());
            SigningCredentials parentCredentials = parentProfile.getCredentials();
            LogWriter.logDebug("Successfully obtained credentials from parent assumer: " + parentProfile.getName());

            Region region = getRegion();
            StsClient stsClient = StsClient.builder()
                    .credentialsProvider(new SigningCredentialConverter(parentCredentials))
                    .region(region)
                    .build();

            final String roleARN = roleArnOptional.get();

            AssumeRoleRequest.Builder requestBuilder = AssumeRoleRequest.builder().roleArn(roleARN);

            final Optional<Integer> durationSecondsOptional = profile.getDurationSeconds();
            if (durationSecondsOptional.isPresent()) {
                int duration = durationSecondsOptional.get();
                //Bounds check 
                if (duration < 900) {
                    duration = 900;
                } else if (duration > 43200) {
                    duration = 43200;
                }
                requestBuilder = requestBuilder.durationSeconds(duration);
            }

            final Optional<String> externalIdOptional = profile.getExternalId();
            if (externalIdOptional.isPresent()) {
                requestBuilder = requestBuilder.externalId(externalIdOptional.get());
            }

            final Optional<String> sessionNameOptional = profile.getSessionName();
            if (sessionNameOptional.isPresent()) {
                requestBuilder = requestBuilder.roleSessionName(sessionNameOptional.get());
            } else {
                //Required but not specified. Let's fall back to a default
                requestBuilder = requestBuilder.roleSessionName("AWSSigner-" + System.currentTimeMillis());
            }

            final Optional<String> sessionPolicyOptional = profile.getSessionPolicy();
            if (sessionPolicyOptional.isPresent()) {
                requestBuilder = requestBuilder.policy(sessionPolicyOptional.get());
            }

            LogWriter.logDebug("Attempting to assume role: " + roleARN);
            AssumeRoleResponse assumeRole = stsClient.assumeRole(requestBuilder.build());
            Credentials awsCredentials = assumeRole.credentials();
            LogWriter.logInfo("Successfully assumed role: " + roleARN);

            return new SigningCredentials(awsCredentials.accessKeyId(), awsCredentials.secretAccessKey(), awsCredentials.sessionToken());

        } catch (SignerCredentialException ex) {
            LogWriter.logError("Error while getting credentials for parent profile " + profile.getAssumerProfile().get().getName() + " for assume role: " + roleArnOptional.orElse("") + "\" resulting in error: " + ex.getMessage());
            throw new SignerCredentialException("Unable to get parent credentials", ex);
        } catch (RuntimeException ex) {
            LogWriter.logError("Error while assume role: " + roleArnOptional.orElse("") + "\" resulting in error: " + ex.getMessage());
            throw new SignerCredentialException("Unable to assume role", ex);
        }

    }

    private Region getRegion() {
        //Try to get a region from the profile itself, or default to us-east-1
        String regionString = profile.getRegion().orElse("us-east-1").toLowerCase();

        //Check if we matched an actual region
        Region matchedRegion = Region.of(regionString);
        if (matchedRegion != null) {
            return matchedRegion;
        } else {
            //Didn't match a region. Default to us-east-1
            return Region.US_EAST_1;
        }
    }

}
