package com.netspi.awssigner.model.persistence;

class ProfileFileKeyConstants {

    /*
     * Keys with this prefix are not standard AWS CLI keys
     */
    static final String CUSTOM_KEY_PREFIX = "signer_";

    //profile required keys
    static final String PROFILE_ENABLED_KEY = CUSTOM_KEY_PREFIX + "enabled";
    static final String PROFILE_IN_SCOPE_ONLY_KEY = CUSTOM_KEY_PREFIX + "in_scope_only";

    //profile optional keys
    static final String PROFILE_SERVICE_KEY = CUSTOM_KEY_PREFIX + "service";
    /*
     * Note: we intentionally have a custom value for region rather than the default
     * AWS "region" key. The "region" key is nice on the CLI for specifying a default
     * region. But in the Signer it is really annoying to import a profile with 
     * default region "us-west-2" and then try to send a request to a "us-east-1"
     * endpoint but it fails because it was signed with "us-west-2"
     */
    static final String PROFILE_REGION_KEY = CUSTOM_KEY_PREFIX + "region";
    static final String PROFILE_KEY_ID_KEY = CUSTOM_KEY_PREFIX + "key_id";

    //static creds keys
    static final String STATIC_CREDS_ACCESS_KEY_KEY = "aws_access_key_id";
    static final String STATIC_CREDS_SECRET_KEY_KEY = "aws_secret_access_key";
    static final String STATIC_CREDS_SESSION_TOKEN_KEY = "aws_session_token";

    //Shared duration key
    static final String DURATION_SECONDS_KEY = "duration_seconds";

    //assume role keys
    static final String ASSUME_ROLE_ROLE_ARN_KEY = "role_arn";
    static final String ASSUME_ROLE_ASSUMER_PROFILE_NAME_KEY = "source_profile";
    static final String ASSUME_ROLE_EXTERNAL_ID_KEY = "external_id";
    static final String ASSUME_ROLE_SESSION_NAME_KEY = "role_session_name";
    static final String ASSUME_ROLE_SESSION_POLICY_KEY = CUSTOM_KEY_PREFIX + "session_policy";

    //command keys
    static final String COMMAND_COMMAND_KEY = "credential_process";
}
