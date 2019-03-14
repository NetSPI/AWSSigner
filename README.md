# AWSSigner
Burp Extension for AWS Sigv4 Signing 

Add your Access Key, Secret Key, Region, and Service to the properties in the extension tab. 

The extension will look for the "X-AMZ-Date" header in all requests being sent by Burp. If it finds a request, it will update the signature in the request. Your request must also have an Authorization header, which should be on all AWS signed requests.

## Example Request

The extenion takes an existing Sigv4 request and updates the Authorization and X-AMZ-Date headers.

Here's an example of a Sigv4 request that the extention will update:

```
GET /?Param1=value1 HTTP/1.1
Host:example.amazonaws.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date:20150830T123600Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190101/us-west-1/test/request, SignedHeaders=content-type;host;x-amz-date, Signature=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

More information about Sigv4 can be found here: 
* https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
* https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

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

