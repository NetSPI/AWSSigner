package com.netspi.awssigner.credentials;

import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.Profile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

public class ProfileCredentialTester {

    private final Profile profile;

    public ProfileCredentialTester(Profile profile) {
        this.profile = profile;
    }

    public SigningCredentials testProfile() throws SignerCredentialException {
        if (!profile.requiredFieldsAreSet()) {
            throw new IllegalStateException("Profile " + profile.getName() + " does not have all required fields set.");
        }

        //Get the credentials
        SigningCredentials creds = profile.getCredentials();
        Region region = Region.US_EAST_1;
        StsClient stsClient = StsClient.builder()
                .credentialsProvider(new SigningCredentialConverter(creds))
                .region(region)
                .build();
        GetCallerIdentityResponse response = stsClient.getCallerIdentity();
        LogWriter.logDebug("Successfully called GetCallerIdentity: " + response.toString());
        return creds;
    }

}
