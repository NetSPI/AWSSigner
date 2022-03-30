# AWSSigner
Burp Extension for AWS SigV4 Signing 

Create a profile in the extension's tab to specify which credentials should be used when signing the request. 

The extension will check each request passing through Burp. If the request has both the "X-Amz-Date" and "Authorization" header, the request will be re-signed with the specified profile's credentials, and the headers updated. 

![AWS Signer](/screenshots/awssigner.png)

## Example Request

The extension takes an existing SigV4 request and updates the Authorization and X-AMZ-Date headers.

Here's an example of a SigV4 request that the extension will update:

```
GET /?Param1=value1 HTTP/1.1
Host: example.amazonaws.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date: 20150830T123600Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190101/us-west-1/test/request, SignedHeaders=content-type;host;x-amz-date, Signature=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

More information about Sigv4 can be found here: 
* https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
* https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

## Extension Tab Interface

The extension's configuration is accessible in Burp Suite under the "AWS Signer" tab. This tab is available in Burp Suite when the extension is added and loaded. 

### Global Settings

These settings influence the entire extension's behavior. The settings include:
* Signing Enabled: If enabled, SigV4 requests will be resigned as they pass through Burp. If disabled, the extension will not modify any requests.
* Always Sign With: If a profile is selected, all applicable requests will be signed with the specified profile. If unset, requests will be signed using the credentials of the profile with the same "Key Id" value.
* Log Level: Controls the extension's log verbosity. 

![Global Settings](/screenshots/global_settings.png)

### Profile Management

This panel adds/removes profiles. The following buttons are available:
* Add: Adds a new static credentials, assume role, or command profile. Newly added profiles must have a unique name.
* Delete: Deletes an existing profile. The extension will check if the profile is referenced by any other existing profiles. 
* Copy: Copies an existing profile. The copy must have a unique name.
* Import: Imports one or more profiles. See the following section for details. 
* Export: Exports the current profile configurations to a user-selected file. 

![Profile Management](/screenshots/profile_management.png)

#### Profile Import
After clicking the profile import button, a pop-up window allows you to import profiles. Click one of the Source buttons to bring in profiles:
* Auto: Automatically sources profiles from default credential files (based on the AWS CLI), the clipboard and environment variables
* File: Allows the user to specify which file to load profiles from. This is useful for importing previously exported profiles. 
* Env: Attempts to import a profile based on the following standardized AWS CLI environment variables:
  * AWS_ACCESS_KEY_ID
  * AWS_SECRET_ACCESS_KEY 
  * AWS_SESSION_TOKEN
* Clipboard: Attempts to automatically recognize and import a profile based on credentials currently copied and held in the user's clipboard. 

After sourcing the profiles, use the checkboxes to select which profiles to import into the extension.

![Profile Import](/screenshots/profile_import.png)

### Profile Configuration
The following settings are available for every profile, regardless of its type:
* Enabled: When checked, the profile is available for signing requests. Otherwise, it will not be used to modify requests.
* In-Scope Only: When checked, the profile will only sign requests that are in-scope (as determined by the URL). Otherwise, it will sign any eligible request.
* Region: When provided, this value replaces the AWS region specified in the request's Authorization header. Otherwise, the request is signed using the same region included in the Authorization header. 
* Service: When provided, this value replaces the AWS service specified in the request's Authorization header. Otherwise, the request is signed using the same service included in the Authorization header. 
* Key Id: When provided, this profile will be used to sign any eligible request whose Authorization header's key id contains the same key id. This can be useful for using one profile to sign certain requests, and have another active profile sign other requests at the same time. This can be any text and does not need to be in the key id format. 

#### Test Profile Credentials Button
This button can be used to test a profile's credentials and ensure they are valid. The credentials are tested by signing a [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) request and ensuring a successful response. The success or failure is reported in the Status field above.

![Profile Configuration](/screenshots/profile_configuration.png)

### Profile Types
There are three types of profiles supported by the extension:
1. Static Credentials: An access key and secret key, with an optional session token. 
2. AssumeRole: The extension will assume a specified role and use the credentials returned. To assume the role, the user must specify another "assumer" profile which will provide credentials required to assume the specified role. 
3. Command: The extension will execute the specified shell command and parse an access key, a secret key and (optionally) a session token.

#### Static Credentials Profile
The user must provide an access key and a secret key. The session token is optional.

#### AssumeRole Profile
The user must provide a role ARN which specifies the role to be assumed. The user must also provide credentials to assume this role. These credentials are provided through an "assumer" profile. This allows chaining multiple profiles and roles together when required. 

The user may provide the following. See this [API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) for further details. 
* Session Name: An identifier for the assumed role session.
* External Id: A unique identifier that might be required when you assume a role in another account.
* Duration: The lifetime of the session (in seconds). The extension will cache the credentials automatically and re-use them when valid. If the duration is set to 0, the credentials will not be cached and new credentials will be fetched for each request to sign. 
* Session Policy Configuration: An IAM policy in JSON format that you want to use as an inline session policy. This is useful for testing different IAM policies quickly without waiting for the IAM policy to propagate and reach eventual consistency. See [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session) for further information on session policies. 

![AssumeRole Profile Configuration](/screenshots/assume_role_profile.png)

#### Command Profile
The user must provide a command to be executed which will return AWS credentials in the form of an access key, secret key and (optionally) session token. The command will be executed using either `cmd` (Windows) or `sh` (non-Windows). The extension will attempt to parse the credentials from the command's stdout output. The output does not have a set format, and the credential extraction is based on pattern matching. 

The user may provide a Duration. The duration is the lifetime of the credentials (in seconds). The extension will cache the credentials automatically and re-use them when valid. If the duration is set to 0, the credentials will not be cached and the command will be executed for each request that must be signed with the profile. 

The extracted credentials show the most recently extracted credentials retrieved by pressing the Test Profile Credentials button. This is intended for debugging purposes. 

![Command Profile Configuration](/screenshots/command_profile.png)

## Context Menu
The extension can be configured by the user while editing a request. Right-click within the request, hover the cusor over Extensions, and then over AWS Signer. The following configuration is available from this location:
1. Enable/Disable Signing: Signing can be enabled or disabled entirely. 
2. Set Default Signing Profile: The default signing profile can be selected or unset here. 

![Context Menu](/screenshots/contextitem.png)

## Download

The most recent JAR file can be found in the releases https://github.com/NetSPI/AWSSigner/releases

## Build

1. git clone https://github.com/NetSPI/AWSSigner.git
2. Install gradle for your distribution (https://gradle.org/install/)
3. cd AWSSigner
4. gradle build
5. Jar file will be in the build/libs directory
