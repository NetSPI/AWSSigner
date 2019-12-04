package burp;

public class HttpRequestResponse implements IHttpRequestResponse{
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    public HttpRequestResponse(byte[] request) {
        this.request = request;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setRequest(byte[] request) {
        this.request = request;
    }

    @Override
    public void setResponse(byte[] response) {
        this.response = response;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public void setHighlight(String highlight) {
        this.highlight = highlight;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}
