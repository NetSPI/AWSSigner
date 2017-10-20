# AWSSigner
Burp Extension for AWS Signing 

![Alt text](/screenshots/awssigner.png?raw=true)

Add your Access Key, Secret Key, Region, and Service to the properties in the extension tab. The extension will look for the "X-AWS-Date" header in all requests being sent by Burp. If it finds a request, it will update the signature in the request.
