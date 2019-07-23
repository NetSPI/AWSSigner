package burp;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    private IExtensionHelpers helpers;
    private PrintWriter pw;
    private JPanel panel;
    private JTextField accessKey;
    private JTextField secretKey;
    private JTextField token;
    private JTextField region;
    private JTextField service;
    private JCheckBox useToken;
    private JCheckBox dynamicRegionAndService;
    private JCheckBox useDefaultProfile;

    private JComboBox profileComboBox;
    private int numProfiles = 0;
    private JButton saveProfileButton;
    private JButton useProfileButton;
    private JButton deleteProfileButton;
    private boolean justDeleted = false;
    private HashMap<Integer, String[]> profiles;
    private int ACCESS_KEY = 0;
    private int SECRET_KEY = 1;
    private int REGION = 2;
    private int SERVICE = 3;
    private int TOKEN = 4;
    private int USE_TOKEN = 5;
    private int DYNAMIC = 6;
    private int READ_CREDS = 7;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        helpers = callbacks.getHelpers();
        this.pw = new PrintWriter(callbacks.getStdout(), true);


        setupTab();

        callbacks.setExtensionName("AWS Signer");

        callbacks.registerContextMenuFactory(new Menu());

        SwingUtilities.invokeLater(() -> {

            callbacks.customizeUiComponent(panel);

            callbacks.addSuiteTab(BurpExtender.this);

            callbacks.registerHttpListener(BurpExtender.this);
        });


    }

    public void createNewProfile() {

        // Add another profile to the combo box, or add the add profile button if it's not already there.
        int boxSize = profileComboBox.getItemCount();
        if (boxSize == 0) {

            // If there's nothing here, just add our add profile button
            this.profileComboBox.addItem(new AWSSignerMenuItem("Add Profile", 0));
        } else {

            // If there is already an add profile button, start creating profiles
            numProfiles++;
            profileComboBox.insertItemAt(new AWSSignerMenuItem("Profile " + numProfiles, numProfiles), boxSize - 1);
            profiles.put(numProfiles, new String[]{"", "", "", "", "", "", "", ""});
            profileComboBox.setSelectedIndex(boxSize - 1);
            clearProfile();

            setMenuItems();
        }
    }

    public void clearProfile() {
        // Reset text fields
        this.accessKey.setText("");
        this.secretKey.setText("");
        this.token.setText("");
        this.region.setText("");
        this.service.setText("");
        this.useToken.setSelected(false);
        this.useDefaultProfile.setSelected(false);
        this.dynamicRegionAndService.setSelected(false);
    }

    public void populateProfile(int profile) {
        this.accessKey.setText(this.profiles.get(profile)[ACCESS_KEY]);
        this.secretKey.setText(this.profiles.get(profile)[SECRET_KEY]);
        this.token.setText(this.profiles.get(profile)[TOKEN]);
        this.region.setText(this.profiles.get(profile)[REGION]);
        this.service.setText(this.profiles.get(profile)[SERVICE]);
        this.useToken.setSelected(Boolean.parseBoolean(this.profiles.get(profile)[USE_TOKEN]));
        this.dynamicRegionAndService.setSelected(Boolean.parseBoolean(this.profiles.get(profile)[DYNAMIC]));
        this.useDefaultProfile.setSelected(Boolean.parseBoolean(this.profiles.get(profile)[READ_CREDS]));
    }

    public void setupTab() {
        // Set up profiles combobox
        this.profiles = new HashMap<Integer, String[]>();

        createNewProfile();
        createNewProfile();

        this.profileComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED && !justDeleted) {
                    int selectedProfile = ((AWSSignerMenuItem) e.getItem()).getProfileNumber();
                    if (selectedProfile == 0) {
                        pw.println("Creating new profile...");
                        createNewProfile();
                    } else {
                        populateProfile(selectedProfile);
                    }
                }
            }
        });

        this.saveProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((AWSSignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                pw.println("Saved profile " + profile + " with key: " + accessKey.getText());
                profiles.put(profile,
                        new String[]{accessKey.getText(),
                                secretKey.getText(),
                                region.getText(),
                                service.getText(),
                                token.getText(),
                                String.valueOf(useToken.isSelected()),
                                String.valueOf(dynamicRegionAndService.isSelected()),
                                String.valueOf(useDefaultProfile.isSelected())});
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        this.deleteProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((AWSSignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                int index = profileComboBox.getSelectedIndex();
                pw.println("Deleting profile " + profile + "...");

                // We need to know this so that when a new item is selected by default by
                // the combobox, we can ignore the action.
                justDeleted = true;
                profileComboBox.removeItemAt(index);
                profiles.remove(profile);

                // Determine how we should move our combobox, and what profile we need to populate
                if (profiles.size() > index) {

                    // There are profiles after this one, move to the newer profile
                    profileComboBox.setSelectedIndex(index);
                    int newProfile = ((AWSSignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                    populateProfile(newProfile);
                } else if (profiles.size() > 0) {

                    // No newer profiles, but there are older ones. Move to the older one
                    profileComboBox.setSelectedIndex(index - 1);
                    int newProfile = ((AWSSignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                    populateProfile(newProfile);
                } else {

                    // No other profiles exist, create a new one
                    createNewProfile();
                }

                // If we just deleted our enabled profile, disable the signer
                if (profile == Menu.getEnabledProfile()) {
                    Menu.setEnabledProfile(0);
                }

                setMenuItems();

                justDeleted = false;
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        this.useProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((AWSSignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                Menu.setEnabledProfile(profile);
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
    }

    // Set the menu items in the context menu
    private void setMenuItems() {
        int itemCount = profileComboBox.getItemCount();
        AWSSignerMenuItem[] menuItems = new AWSSignerMenuItem[itemCount - 1];

        // Skip the first item, it's just the add profile button
        for (int i = 0; i < itemCount - 1; i++) {
            menuItems[i] = (AWSSignerMenuItem) profileComboBox.getItemAt(i);
        }

        Menu.setMenuItems(menuItems);
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

        if(messageIsRequest) {
            if (Menu.getEnabledProfile() > 0) {
                IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());

                java.util.List<String> headers = request.getHeaders();

                if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("x-amz-date")))) {
                    String[] profile = this.profiles.get(Menu.getEnabledProfile());
                    byte[] signedRequest;
                    if (useDefaultProfile.isSelected() && profile[ACCESS_KEY].isEmpty()) {
                        String currentUsersHomeDir = System.getProperty("user.home");
                        try {
                            File f = new File(currentUsersHomeDir + "/.aws/credentials");
                            BufferedReader br = new BufferedReader(new FileReader(f));
                            String st;
                            int i = -1;
                            while ((st = br.readLine()) != null) {
                                if (st.equalsIgnoreCase("[default]")) {
                                    i = 0;
                                } else if (i == 0 && st.startsWith("aws_access_key_id")) {
                                    profile[ACCESS_KEY] = st.split(" ")[2];
                                } else if (i == 0 && st.startsWith("aws_secret_access_key")) {
                                    profile[SECRET_KEY] = st.split(" ")[2];
                                } else if (i == 0 && st.startsWith("aws_security_token")) {
                                    profile[TOKEN] = st.split(" ")[2];
                                } else {
                                    i = -1;
                                }
                            }
                            br.close();
                        } catch (Exception e) {
                            pw.println("Error reading credentials file: " + e.getMessage());
                        }
                    }
                    if (dynamicRegionAndService.isSelected()) {
                        String region = "";
                        String service = "";
                        profile[REGION] = region;
                        profile[SERVICE] = service;
                        for(String header : headers) {
                            if (header.toLowerCase().startsWith("authorization:")){
                                String[] splitCredential = header.split("=")[1].split("/");
                                region = splitCredential[2];
                                service = splitCredential[3];
                            }
                        }
                        pw.println("Signing with profile " + Menu.getEnabledProfile() + " with key: " + profile[ACCESS_KEY]);
                        if (Boolean.parseBoolean(profile[USE_TOKEN])) {
                            signedRequest = Utility.signRequest(messageInfo,
                                    helpers,
                                    service,
                                    region,
                                    profile[ACCESS_KEY],
                                    profile[SECRET_KEY],
                                    profile[TOKEN],
                                    pw);
                        } else {
                            signedRequest = Utility.signRequest(messageInfo,
                                    helpers,
                                    service,
                                    region,
                                    profile[ACCESS_KEY],
                                    profile[SECRET_KEY],
                                    "",
                                    pw);
                        }
                        messageInfo.setRequest(signedRequest);
                    } else if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains(profile[SERVICE]))) &&
                            headers.stream().anyMatch((str -> str.trim().toLowerCase().contains(profile[REGION])))) {
                        pw.println("Signing with profile " + Menu.getEnabledProfile() + " with key: " + profile[ACCESS_KEY]);
                        if (Boolean.parseBoolean(profile[USE_TOKEN])) {
                            signedRequest = Utility.signRequest(messageInfo,
                                    helpers,
                                    profile[SERVICE],
                                    profile[REGION],
                                    profile[ACCESS_KEY],
                                    profile[SECRET_KEY],
                                    profile[TOKEN],
                                    pw);
                        } else {
                            signedRequest = Utility.signRequest(messageInfo,
                                    helpers,
                                    profile[SERVICE],
                                    profile[REGION],
                                    profile[ACCESS_KEY],
                                    profile[SECRET_KEY],
                                    "",
                                    pw);
                        }
                        messageInfo.setRequest(signedRequest);
                    } else {
                        messageInfo.setRequest(messageInfo.getRequest());
                        pw.println("Request not in defined region and service, not signing");
                    }
                }
            }
        }

    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panel = new JPanel();
        panel.setLayout(new GridLayoutManager(10, 2, new Insets(0, 0, 0, 0), -1, -1));
        final JLabel label1 = new JLabel();
        label1.setText("Access Key: ");
        panel.add(label1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        accessKey = new JTextField();
        panel.add(accessKey, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Secret Key:");
        panel.add(label2, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Session Token:");
        panel.add(label6, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Region: ");
        panel.add(label3, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Service: ");
        panel.add(label4, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretKey = new JTextField();
        panel.add(secretKey, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        token = new JTextField();
        panel.add(token, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        region = new JTextField();
        panel.add(region, new GridConstraints(4, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        service = new JTextField();
        panel.add(service, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel.add(spacer1, new GridConstraints(9, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Profile:");
        panel.add(label5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        profileComboBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        profileComboBox.setModel(defaultComboBoxModel1);
        panel.add(profileComboBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveProfileButton = new JButton();
        saveProfileButton.setText("Save Profile");
        useToken = new JCheckBox();
        useToken.setText("Use session token?");
        panel.add(useToken, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        dynamicRegionAndService = new JCheckBox();
        dynamicRegionAndService.setText("Dynamically load region and service from request?");
        panel.add(dynamicRegionAndService, new GridConstraints(6, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        useDefaultProfile = new JCheckBox();
        useDefaultProfile.setText("Use default credentials from ~" + File.separator + ".aws" + File.separator + "credentials?");
        panel.add(useDefaultProfile, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        panel.add(saveProfileButton, new GridConstraints(8, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel.add(panel1, new GridConstraints(9, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel.add(panel2, new GridConstraints(8, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        deleteProfileButton = new JButton();
        deleteProfileButton.setText("Delete Profile");
        panel2.add(deleteProfileButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        useProfileButton = new JButton();
        useProfileButton.setText("Use Profile");
        panel2.add(useProfileButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel;
    }
}
