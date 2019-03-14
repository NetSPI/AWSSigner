# AWSSigner
Burp Extension for AWS Sigv4 Signing 

Add your Access Key, Secret Key, Region, and Service to the properties in the extension tab. 

The extension will look for the "X-AMZ-Date" header in all requests being sent by Burp. If it finds a request, it will update the signature in the request. Your request must also have an Authorization header, which should be on all AWS signed requests.


![Alt text](/screenshots/awssigner.png?raw=true)

![Alt text](/screenshots/contextitem.png?raw=true)

