# AWSSigner
Burp Extension for AWS Sigv4 Signing 

Add your Access Key, Secret Key, Region, and Service to the properties in the extension tab. 

The extension will look for the "X-AMZ-Date" header in all requests being sent by Burp. If it finds a request, it will update the signature in the request. Your request must also have an Authorization header, which should be on all AWS signed requests.

## Download

The most recent jar file can be found in the releases https://github.com/NetSPI/AWSSigner/releases

## Build

1. git clone https://github.com/NetSPI/AWSSigner.git
2. Install gradle for your distribution (https://gradle.org/install/)
3. cd AWSSigner
4. gradle build
5. Jar file will be in the build/libs directory

![Alt text](/screenshots/awssigner.png?raw=true)

![Alt text](/screenshots/contextitem.png?raw=true)

