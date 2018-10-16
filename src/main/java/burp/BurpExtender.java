package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.util.HashMap;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener
{

    private IExtensionHelpers helpers;
    private PrintWriter pw;
    private JPanel panel;
    private JTextField accessKey;
    private JTextField secretKey;
    private JTextField region;
    private JTextField service;

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

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

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
            profiles.put(numProfiles, new String[]{"", "", "", ""});
            profileComboBox.setSelectedIndex(boxSize-1);
            clearProfile();

            setMenuItems();
        }
    }

    public void clearProfile() {
        // Reset text fields
        this.accessKey.setText("");
        this.secretKey.setText("");
        this.region.setText("");
        this.service.setText("");
    }

    public void populateProfile(int profile) {
        this.accessKey.setText(this.profiles.get(profile)[ACCESS_KEY]);
        this.secretKey.setText(this.profiles.get(profile)[SECRET_KEY]);
        this.region.setText(this.profiles.get(profile)[REGION]);
        this.service.setText(this.profiles.get(profile)[SERVICE]);
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
                        new String[] {accessKey.getText(),
                            secretKey.getText(),
                            region.getText(),
                            service.getText()});
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
                    profileComboBox.setSelectedIndex(index-1);
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
        AWSSignerMenuItem[] menuItems = new AWSSignerMenuItem[itemCount-1];

        // Skip the first item, it's just the add profile button
        for (int i=0; i<itemCount-1; i++) {
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

        if (Menu.getEnabledProfile() > 0) {
            IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());

            java.util.List<String> headers = request.getHeaders();

            if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains("x-amz-date")))){
                String[] profile = this.profiles.get(Menu.getEnabledProfile());
                pw.println("Signing with profile " + Menu.getEnabledProfile() + " with key: " + profile[ACCESS_KEY]);
                byte[] signedRequest = Utility.signRequest(messageInfo,
                        helpers,
                        profile[SERVICE],
                        profile[REGION],
                        profile[ACCESS_KEY],
                        profile[SECRET_KEY]);

                messageInfo.setRequest(signedRequest);

            }
        }


    }
}
