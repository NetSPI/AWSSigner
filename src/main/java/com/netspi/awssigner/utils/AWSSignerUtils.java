package com.netspi.awssigner.utils;

import com.netspi.awssigner.log.LogWriter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.util.Base64;
import java.util.UUID;

public final class AWSSignerUtils {
    private static String CONFIG_URL_STRING = "aws-signer-project-config";

    private static IBurpExtenderCallbacks callbacks;
    private static IHttpService httpService;

    public static void setBurpExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        AWSSignerUtils.callbacks = callbacks;
        httpService = callbacks.getHelpers().buildHttpService(CONFIG_URL_STRING, 65535, true);
    }

    // Fetches a base64 encoded, serialized object as a burp setting on a per-project basis
    public static Object getStoredObjectForCurrentProject(String key) {
        String projectUUIDString = getOrGenerateProjectUUID();
        LogWriter.logDebug("Project UUID string is: " + projectUUIDString);

        String base64 = callbacks.loadExtensionSetting(projectUUIDString+ "-" + key);

        Object result = null;

        if ( base64 != null ){
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    
                result = ois.readObject();
            } catch ( Exception e ) {
                e.printStackTrace();
            }
        }

        return result;
    }

    // Stores a base64 encoded, serialized object as a burp setting on a per-project basis
    public static void storeObjectForCurrentProject(String key, Object value) {
        String projectUUIDString = getOrGenerateProjectUUID();
        LogWriter.logDebug("Project UUID string is: " + projectUUIDString);

        try {

            ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(outputBuffer);
            oos.writeObject(value);

            byte[] serializedObject = outputBuffer.toByteArray();

            String base64 = Base64.getEncoder().encodeToString(serializedObject);

            callbacks.saveExtensionSetting(projectUUIDString + "-" + key, base64);            
        } catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static String getOrGenerateProjectUUID() {
        IHttpRequestResponse[] sitemap = callbacks.getSiteMap(httpService.getProtocol() +"://" + httpService.getHost() + ":" + httpService.getPort() + "/" + CONFIG_URL_STRING);

        String uuidString = null;

        // UUID for this project hasnt been generated yet
        if (sitemap.length == 0) {
            uuidString = UUID.randomUUID().toString();
            HttpResponseWrapper uuid = new HttpResponseWrapper();

            try {

                // Generate a fabricated request in the sitemap to store the UUID in the project for future retreival
                // This is needed as the legacy API does not support distinguishing what project we are in natively

                byte[] buffer = callbacks.getHelpers().buildHttpRequest(new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/" + CONFIG_URL_STRING));
                uuid.setRequest(buffer);
                uuid.setResponse(uuidString.getBytes());
                uuid.setHttpService(httpService);

                uuid.setRequest(buffer);
                callbacks.addToSiteMap(uuid);
            } catch ( Exception e ){
                e.printStackTrace();
            }
        } else {
            uuidString = new String(sitemap[0].getResponse());
        }

        LogWriter.logDebug("Using project UUID: " + uuidString);

        return uuidString;
    }

    // Used as a wrapper "HttpRequestResponse" object we can store in the sitemap, but we use it to just store arbitrary data in the response buffer.
    static class HttpResponseWrapper implements IHttpRequestResponse {

        private byte[] requestData;
        private byte[] responseData;
        private IHttpService service;

        @Override
        public byte[] getRequest() {
            return requestData;
        }

        @Override
        public void setRequest(byte[] message) {
            this.requestData = message;
        }

        @Override
        public byte[] getResponse() {
            return responseData;
        }

        @Override
        public void setResponse(byte[] message) {
            this.responseData = message;
        }

        @Override
        public String getComment() {
            return null;
        }

        @Override
        public void setComment(String comment) {}

        @Override
        public String getHighlight() {
            return null;
        }

        @Override
        public void setHighlight(String color) {}

        @Override
        public IHttpService getHttpService() {
            return service;
        }

        @Override
        public void setHttpService(IHttpService httpService) {
            this.service = httpService;
        }
    }
}