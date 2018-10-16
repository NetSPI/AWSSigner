package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener
{

    private IExtensionHelpers helpers;
    private JPanel panel;
    private JTextField accessKey;
    private JTextField secretKey;
    private JTextField region;
    private JTextField service;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("AWS Signer");

        callbacks.registerContextMenuFactory(new Menu());

        SwingUtilities.invokeLater(() -> {

            callbacks.customizeUiComponent(panel);

            callbacks.addSuiteTab(BurpExtender.this);

            callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "AWS Signer";
    }
    @Override
    public Component getUiComponent() {
        return panel;
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) throws Exception {

        if (Menu.getStatus()) {
            IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());

            java.util.List<String> headers = request.getHeaders();

            if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("x-amz-date")))){

                byte[] signedRequest = Utility.signRequest(messageInfo, helpers, service.getText(), region.getText(), accessKey.getText(), secretKey.getText());

                messageInfo.setRequest(signedRequest);

            }
        }


    }
}
