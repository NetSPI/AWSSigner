package burp;

import javax.swing.*;
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

        SwingUtilities.invokeLater(() -> {
            panel = new JPanel(new BorderLayout());

            JPanel labels = new JPanel(new GridLayout(0, 1));
            JPanel inputs = new JPanel(new GridLayout(0, 1));

            panel.add(labels, BorderLayout.WEST);
            panel.add(inputs, BorderLayout.CENTER);

            accessKey = new JTextField();
            secretKey = new JTextField();
            region = new JTextField();
            service = new JTextField();

            labels.add(new JLabel("Access Key: "), BorderLayout.WEST);
            inputs.add(accessKey, BorderLayout.CENTER);
            labels.add(new JLabel("Secret Key: "), BorderLayout.WEST);
            inputs.add(secretKey, BorderLayout.CENTER);
            labels.add(new JLabel("Region: "), BorderLayout.WEST);
            inputs.add(region, BorderLayout.CENTER);
            labels.add(new JLabel("Service: "), BorderLayout.WEST);
            inputs.add(service, BorderLayout.CENTER);

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

        IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());

        java.util.List<String> headers = request.getHeaders();

        if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("x-amz-date")))){

            byte[] signedRequest = Utility.signRequest(messageInfo, helpers, service.getText(), region.getText(), accessKey.getText(), secretKey.getText());

            messageInfo.setRequest(signedRequest);

        }
    }
}
