package burp;

import com.netspi.awssigner.signing.AwsRequestSigner;
import com.netspi.awssigner.controller.AWSSignerController;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.AWSSignerConfiguration;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.signing.DelegatingAwsRequestSigner;
import com.netspi.awssigner.signing.ParsedAuthHeader;
import com.netspi.awssigner.signing.SigningException;
import com.netspi.awssigner.utils.AWSSignerUtils;
import com.netspi.awssigner.view.BurpUIComponentCustomizer;
import com.netspi.awssigner.view.BurpTabPanel;
import java.awt.Component;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

//This is the Burp primary class. It needs to live in this package and have this name
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    static {
        final Map<Integer, String> tempMap = new HashMap<Integer, String>();

        tempMap.put(IBurpExtenderCallbacks.TOOL_SUITE, "All");
        tempMap.put(IBurpExtenderCallbacks.TOOL_EXTENDER, "Extensions");
        tempMap.put(IBurpExtenderCallbacks.TOOL_INTRUDER, "Intruder");
        tempMap.put(IBurpExtenderCallbacks.TOOL_PROXY, "Proxy");
        tempMap.put(IBurpExtenderCallbacks.TOOL_REPEATER, "Repeater");
        tempMap.put(IBurpExtenderCallbacks.TOOL_SCANNER, "Scanner");
        tempMap.put(IBurpExtenderCallbacks.TOOL_SEQUENCER, "Sequencer");
        tempMap.put(IBurpExtenderCallbacks.TOOL_TARGET, "Target");

        TOOL_FLAG_TRANSLATION_MAP = Collections.unmodifiableMap(tempMap);
    }
    public static final String EXTENSION_NAME = "AWS Signer";

    private static final Map<Integer, String> TOOL_FLAG_TRANSLATION_MAP;

    private BurpTabPanel view;
    private AWSSignerConfiguration model;
    private AWSSignerController controller;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        //Save callbacks and helpers for later reference
        this.callbacks = callbacks;
        AWSSignerUtils.setBurpExtenderCallbacks(callbacks);
        helpers = callbacks.getHelpers();

        // Extension unload/shutdown callback
        this.callbacks.registerExtensionStateListener(()-> {
            this.model.persist();
        });

        //Setup styling
        BurpUIComponentCustomizer.setBurpStyler((Component component) -> {
            callbacks.customizeUiComponent(component);
        });

        //Logging
        LogWriter.configure(callbacks.getStdout(), callbacks.getStderr());
        LogWriter.logDebug("Logging configured");

        //Create the view
        view = new BurpTabPanel();
        //Create the model
        model = AWSSignerConfiguration.getOrCreateProjectConfiguration();
        //Create controller to keep them in sync
        controller = new AWSSignerController(view, model);

        //register with Burp
        //set our extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        //register ourselves with Burp
        //callbacks.registerContextMenuFactory(new Menu());
        SwingUtilities.invokeLater(() -> {
            callbacks.addSuiteTab(BurpExtender.this);
            callbacks.registerContextMenuFactory(BurpExtender.this);
            callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        //Apply Burp Styling
        BurpUIComponentCustomizer.applyBurpStyling(view);
        return view;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = controller.getMenuItems(invocation);
        menuItems.forEach(BurpUIComponentCustomizer::applyBurpStyling);
        return menuItems;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        LogWriter.logDebug("Handling incoming HTTP message.");

        //Check if it's a request. We only sign requests
        if (!messageIsRequest) {
            LogWriter.logDebug("Ignoring response.");
            return;
        }

        //Is the signer enabled?
        if (!model.isEnabled) {
            LogWriter.logDebug("Signing not enabled. Ignoring Message.");
            return;
        }

        // Is the request from a tool we want to sign?
        if ((model.signForTools & toolFlag) == 0 && (model.signForTools & IBurpExtenderCallbacks.TOOL_SUITE) == 0) {
            LogWriter.logDebug("Signing for requests from " + TOOL_FLAG_TRANSLATION_MAP.get(toolFlag) + " is not enabled. Ignoring Message.");
            return;
        }

        //Could be a request we want to sign. Let's analyze it
        IRequestInfo request = helpers.analyzeRequest(messageInfo);

        //Check if this is a SigV4 request
        if (!isSigV4Request(request)) {
            LogWriter.logDebug("Message is not a SigV4 request.");
            return;
        }

        Optional<ParsedAuthHeader> authHeaderOptional = parseAuthHeader(request);
        if (authHeaderOptional.isEmpty()) {
            LogWriter.logError("Unable to parse Authorization header from headers: " + request.getHeaders());
            return;
        }
        ParsedAuthHeader authHeader = authHeaderOptional.get();

        //Try to get the right profile for signing
        Optional<Profile> profileOptional = getSigningProfileForRequest(authHeader);

        //Check if we even found a profile
        if (profileOptional.isEmpty()) {
            LogWriter.logDebug("Unable to identify correct profile for message.");
            return;
        }

        Profile profile = profileOptional.get();

        //Check to see if this profile is even ready for signing
        //This isn't a guarentee, but a quick assessment if it's NOT ready
        if (!profile.requiredFieldsAreSet()) {
            LogWriter.logDebug("Signing profile \"" + profile.getName() + "\" does not have all required fields set. Skipping request.");
            return;
        }

        //Check to see if this profile is enabled
        if (!profile.isEnabled()) {
            LogWriter.logDebug("Signing profile \"" + profile.getName() + "\" is not enabled. Skipping request.");
            return;
        }

        //Check to see if the profile only signs in-scope requests
        if (profile.isInScopeOnly()) {
            //Check if our request is in-scope
            if (!callbacks.isInScope(request.getUrl())) {
                LogWriter.logDebug("Signing profile \"" + profile.getName() + "\" only signs in-scope requests. "
                        + "The current request is out of scope with URL " + request.getUrl() + " Skipping request");
                return;
            }
        }

        //Looks like we should be good for signing! Let's go
        //AwsRequestSigner signer = new ClassicAwsRequestSigner(helpers, profile);
        AwsRequestSigner signer = new DelegatingAwsRequestSigner(helpers, profile);
        try {
            byte[] signedRequest = signer.sign(messageInfo, request, authHeader);
            //Update our message to point to the signed request
            messageInfo.setRequest(signedRequest);
            //Add a comment for later identification
            LogWriter.logInfo("Successfully signed request with profile: " + profile.getName());
            messageInfo.setComment(String.format("%s signed w/ %s", EXTENSION_NAME, profile.getName()));
        } catch (SigningException e) {
            String error = "Unable to sign request with profile "
                    + profile.getName() + " due to exception: " + e.getMessage();
            LogWriter.logError(error);
            callbacks.issueAlert(error);//Not sure if this is helpful
        }
    }

    private Optional<ParsedAuthHeader> parseAuthHeader(IRequestInfo request) {
        //Start by dissecting the Authorization header
        List<String> headers = request.getHeaders();
        return headers.stream().map(header -> header.trim()) //Trim
                .map(ParsedAuthHeader::parseFromAuthorizationHeader) //Try to parse if it's the authorization header
                .filter(Optional::isPresent) //Only keep successfully parsed header
                .map(Optional::get) //Unwrap optional
                .findFirst(); //Keep the first match
    }

    private boolean isSigV4Request(IRequestInfo request) {
        List<String> headers = request.getHeaders();

        //This is how v1 decided if it should be signed
        //Looks for both x-amz-date AND authorization
        return (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("x-amz-date")))
                && headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("authorization"))));
    }

    private Optional<Profile> getSigningProfileForRequest(ParsedAuthHeader authHeader) {
        //If we have a default profile set, just use it
        if (model.alwaysSignWithProfile != null) {
            return Optional.of(model.alwaysSignWithProfile);
        }

        String headerAccessKey = authHeader.getAccessKey();

        //Check if any of the profiles are using this access key as their key id
        Optional<Profile> accessKeyMatchedProfileOptional = model.profiles.stream().filter(profile -> {
            return profile.getKeyId().isPresent();
        }).filter(profile -> {
            return headerAccessKey.trim().equals(profile.getKeyId().get().trim());
        }).findFirst();

        if (accessKeyMatchedProfileOptional.isPresent()) {
            LogWriter.logDebug("Auth header access key \"" + headerAccessKey + "\" matched profile: " + accessKeyMatchedProfileOptional.get().getName());
        } else {
            LogWriter.logDebug("Auth header access key \"" + headerAccessKey + "\" did not match a profile.");
        }

        return accessKeyMatchedProfileOptional;
    }
}
