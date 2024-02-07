package com.netspi.awssigner.controller;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netspi.awssigner.credentials.ProfileCredentialTester;
import com.netspi.awssigner.log.LogLevel;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import com.netspi.awssigner.model.AWSSignerConfiguration;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.view.AddProfileDialog;
import com.netspi.awssigner.view.BurpTabPanel;
import java.awt.CardLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import javax.swing.DefaultListModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import static com.netspi.awssigner.log.LogWriter.*;
import com.netspi.awssigner.model.persistence.ProfileExporter;
import com.netspi.awssigner.view.BurpUIComponentCustomizer;
import com.netspi.awssigner.view.CopyProfileDialog;
import com.netspi.awssigner.view.ImportDialog;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.stream.Collectors;
import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JRadioButtonMenuItem;

/**
 * The complex class which enforces logic and syncs up the configuration model
 * and the UI view.
 */
public class AWSSignerController {

    private final BurpTabPanel view;
    private final AWSSignerConfiguration model;

    private final static String INIT_PROFILE_NAME = "Profile 1";

    //Need these because we have to add and remove when setting up / updating combo boxes
    private ComboBoxProfileSelectionListener alwaysSignWithComboBoxProfileSelectionListener;
    private ComboBoxProfileSelectionListener assumerProfileComboBoxProfileSelectionListener;

    public AWSSignerController(BurpTabPanel view, AWSSignerConfiguration model) {
        this.view = view;
        this.model = model;

        initListeners();

        //Add the initial profile if no profiles exist already

        if (this.model.profiles.isEmpty()) {
            addProfile(new StaticCredentialsProfile(INIT_PROFILE_NAME));
        } else {
            this.view.profileList.setSelectedIndex(0);
        }

        syncViewWithModel();
    }

    private void syncViewWithModel(){

        //Setup profile list
        DefaultListModel listModel = resetProfileList();
        view.profileList.setSelectedIndex(0);

        //Reset "Always Sign With" combo box
        resetAlwaysSignWithProfileComboBox();

        initializeProfileConfigurationTab(model.profiles.get(0));

        // Hack to preserve the state of the flag bits, since the handlers for setSelected flip the bits currently.
        
        int tmp = model.signForTools;
        this.view.persistConfigurationCheckbox.setSelected(model.shouldPersist);
        this.view.signingEnabledCheckbox.setSelected(model.isEnabled);
        this.view.signForAllCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_SUITE) != 0);
        this.view.signForProxyCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_PROXY) != 0);
        this.view.signForIntruderCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_INTRUDER) != 0);
        this.view.signForExtensionsCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_EXTENDER) != 0);
        this.view.signForRepeaterCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_REPEATER) != 0);
        this.view.signForTargetCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_TARGET) != 0);
        this.view.signForScannerCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_SCANNER) != 0);
        this.view.signForSequencerCheckbox.setSelected((model.signForTools & IBurpExtenderCallbacks.TOOL_SEQUENCER) != 0);
        model.signForTools = tmp;
    }

    private void initListeners() {
        //Global signing checkbox
        view.signingEnabledCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("Global Signing Enabled Checkbox State Change.");
            model.isEnabled = (e.getStateChange() == ItemEvent.SELECTED);
            logInfo("Signing Enabled: " + model.isEnabled);
        });

        //Configuration persistence checkbox
        view.persistConfigurationCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("Persist Configuration Checkbox State Change.");
            model.shouldPersist = (e.getStateChange() == ItemEvent.SELECTED);
            logInfo("Persist Configuration Enabled: " + model.shouldPersist);
        });

        //"Always Sign With" profile selection combox box
        alwaysSignWithComboBoxProfileSelectionListener = new ComboBoxProfileSelectionListener(model, "Always Sign With", (Profile profile) -> {
            logDebug("Setting \"Always Sign With\" Profile to: " + profile);
            model.alwaysSignWithProfile = profile;
        });
        view.alwaysSignWithProfileComboBox.addItemListener(alwaysSignWithComboBoxProfileSelectionListener);

        //Logging Level combox box
        view.logLevelComboBox.addItemListener(((event) -> {
            logDebug("Log Level ComboBox Item Event:" + " StateChange: " + event.getStateChange() + " Item: " + event.getItem());
            if (event.getStateChange() == ItemEvent.SELECTED) {
                String selectedLoggingLevel = (String) event.getItem();
                LogLevel newLoggingLevel = LogLevel.valueOf(selectedLoggingLevel.toUpperCase());
                logDebug("New logging level set to: " + newLoggingLevel);
                LogWriter.setLevel(newLoggingLevel);
            }
        }));

        //Sign for all check box
        view.signForAllCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_SUITE;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });
        
        //Sign for repeater check box
        view.signForRepeaterCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_REPEATER;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign for proxy check box
        view.signForProxyCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_PROXY;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign for intruder check box
        view.signForIntruderCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_INTRUDER;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign target check box
        view.signForTargetCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_TARGET;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign for extensions check box
        view.signForExtensionsCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_EXTENDER;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign for sequencer check box
        view.signForSequencerCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_SEQUENCER;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Sign for scanner check box
        view.signForScannerCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("signForTools before: " + Integer.toBinaryString(model.signForTools));
            model.signForTools = model.signForTools ^ IBurpExtenderCallbacks.TOOL_SCANNER;
            logDebug("signForTools after: " + Integer.toBinaryString(model.signForTools));
        });

        //Add button
        view.addProfileButton.addActionListener(((ActionEvent e) -> {
            logDebug("Add Profile Button Clicked.");
            final AddProfileDialog dialog = new AddProfileDialog(null, true, model.getProfileNames());
            BurpUIComponentCustomizer.applyBurpStyling(dialog);
            dialog.pack();
            dialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(view));
            Optional<Profile> addProfileResult = dialog.showDialog();
            if (addProfileResult.isPresent()) {
                Profile newProfile = addProfileResult.get();
                logInfo("New profile to be added from Add dialog: " + newProfile);
                addProfile(newProfile);
            } else {
                logInfo("No new profile returned from Add dialog.");
            }
        }));

        //Delete button
        view.deleteProfileButton.addActionListener(((ActionEvent e) -> {
            logDebug("Delete Profile Button Clicked.");

            Optional<Profile> currentSelectedProfileOptional = getCurrentSelectedProfile();
            if (currentSelectedProfileOptional.isEmpty()) {
                logError("There is no current profile selected. Cannot delete.");
                return;
            }
            final Profile selectedProfile = currentSelectedProfileOptional.get();
            final String selectedProfileName = selectedProfile.getName();

            //Check if selectedProfile is allowed to be deleted.
            //No other profile must use this one as the assumer
            List<String> dependentProfileNames = model.profiles.stream().filter(profile -> {
                return profile instanceof AssumeRoleProfile
                        && ((AssumeRoleProfile) profile).getAssumerProfile().isPresent()
                        && ((AssumeRoleProfile) profile).getAssumerProfile().get().getName().equals(selectedProfileName);
            }).map(Profile::getName).collect(Collectors.toList());
            if (!dependentProfileNames.isEmpty()) {
                JOptionPane.showMessageDialog(SwingUtilities.getWindowAncestor(view),
                        "Cannot delete profile \"" + selectedProfileName + "\" as it is the assumer profile for the following profile(s): " + dependentProfileNames,
                        "Cannot Delete Profile", JOptionPane.ERROR_MESSAGE);
                return;
            }

            //Check if the selected profile is currently the default profile
            if (model.alwaysSignWithProfile != null && model.alwaysSignWithProfile.getName().equals(selectedProfileName)) {
                JOptionPane.showMessageDialog(SwingUtilities.getWindowAncestor(view),
                        "Cannot delete profile \"" + selectedProfileName + "\" because it is the current default profile.",
                        "Cannot Delete Profile", JOptionPane.ERROR_MESSAGE);
                return;
            }

            //Looks good, we should be able to delete.
            //Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(SwingUtilities.getWindowAncestor(view),
                    "Are you sure you want to delete profile " + selectedProfileName + "?",
                    "Confirm Profile Delete",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (result == JOptionPane.YES_OPTION) {
                logInfo("Deletion was confirmed");
                deleteProfile(selectedProfile);
            } else {
                logInfo("Deletion was not confirmed");
            }
        }));

        //Copy button
        view.copyProfileButton.addActionListener(((ActionEvent e) -> {
            logDebug("Copy Profile Button Clicked.");
            Optional<Profile> optionalCurrentProfile = getCurrentSelectedProfile();
            if (optionalCurrentProfile.isEmpty()) {

            } else {
                Profile currentSelectedProfile = optionalCurrentProfile.get();
                logInfo("Copying profile: " + currentSelectedProfile.getName());
                final CopyProfileDialog dialog = new CopyProfileDialog(null, true, model.getProfileNames(), currentSelectedProfile);
                BurpUIComponentCustomizer.applyBurpStyling(dialog);
                dialog.pack();
                dialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(view));
                Optional<Profile> copyProfileResult = dialog.showDialog();
                if (copyProfileResult.isPresent()) {
                    Profile newProfile = copyProfileResult.get();
                    logInfo("New profile to be added from Copy dialog: " + newProfile);
                    addProfile(newProfile);
                } else {
                    logInfo("No new profile returned from Copy dialog.");
                }
            }
        }));

        //Import button
        view.importProfilesButton.addActionListener(((ActionEvent e) -> {
            logDebug("Import Profile Button Clicked.");
            final ImportDialog dialog = new ImportDialog(null, true, model.getProfileNames());
            BurpUIComponentCustomizer.applyBurpStyling(dialog);
            dialog.pack();
            dialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(view));
            Optional<List<Profile>> importProfilesResult = dialog.showDialog();
            if (importProfilesResult.isPresent()) {
                List<Profile> importedProfiles = importProfilesResult.get();
                logInfo("New profiles to be added from import dialog: " + importedProfiles);
                importedProfiles.stream().forEachOrdered(this::addProfile);
            } else {
                logInfo("No new profiles returned from import dialog.");
            }
        }));

        //Export button
        view.exportProfilesButton.addActionListener(((ActionEvent e) -> {
            logDebug("Export Profile Button Clicked.");
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(SwingUtilities.getWindowAncestor(view)) == JFileChooser.APPROVE_OPTION) {
                Path exportPath = fileChooser.getSelectedFile().toPath();
                ProfileExporter exporter = new ProfileExporter(exportPath);
                try {
                    exporter.exportProfiles(model.profiles);
                } catch (IOException ex) {
                    logError("Unable to export profiles to file " + exportPath + " due to exception: " + ex);
                }
            }
        }));

        //Selected profile
        view.profileList.addListSelectionListener((ListSelectionEvent e) -> {
            boolean valueIsAdjusting = e.getValueIsAdjusting();
            String selectedProfileName = view.profileList.getSelectedValue();
            logDebug("Profile List Item Selected."
                    + " ValueIsAdjusting: " + valueIsAdjusting
                    + " FirstIndex: " + e.getFirstIndex()
                    + " LastIndex: " + e.getLastIndex()
                    + " Selected Profile Name: " + selectedProfileName);

            //We only care about the final result
            if (!valueIsAdjusting && selectedProfileName != null) {
                logInfo("Profile List Item Selected Value: " + selectedProfileName);
                Profile selectedProfile = model.getProfileForName(selectedProfileName).get();
                //Update the display to show the profile's configuration.
                initializeProfileConfigurationTab(selectedProfile);
            }

        });

        //Profile enabled checkbox 
        view.profileEnabledCheckbox.addItemListener((ItemEvent e) -> {
            handleProfileConfigurationCheckboxEvent(e, "Signing Enabled", Profile::setEnabled);
        });

        //Profile in-scope-only checkbox 
        view.profileInScopeOnlyCheckbox.addItemListener((ItemEvent e) -> {
            handleProfileConfigurationCheckboxEvent(e, "In-Scope Only Checkbox", Profile::setInScopeOnly);
        });

        //Profile Region text field
        view.profileRegionTextField.addFocusListener(new TextComponentFocusListener<>(this, "Region", Profile::setRegion));

        //Profile Service text field
        view.profileServiceTextField.addFocusListener(new TextComponentFocusListener<>(this, "Service", Profile::setService));

        //Profile Key Id text field
        view.profileKeyIdTextField.addFocusListener(new TextComponentFocusListener<>(this, "Key Id", Profile::setKeyId));

        //Test credentials button
        view.testProfileButton.addActionListener(((ActionEvent e) -> {
            logDebug("Test Credentials Button Clicked.");
            
            Optional<Profile> currentProfileOptional = getCurrentSelectedProfile();
            if (currentProfileOptional.isEmpty()) {
                logDebug("There is no currently selected profile to test credentials for.");
                return;
            }

            Profile profile = currentProfileOptional.get();

            // Bug fix to use the updated config if the input text field still has focus
            if (profile instanceof StaticCredentialsProfile) {
                if (view.staticAccessKeyTextField.hasFocus()) {
                    ((StaticCredentialsProfile) profile).setAccessKey(view.staticAccessKeyTextField.getText());
                }
                if (view.staticSecretKeyTextField.hasFocus()) {
                    ((StaticCredentialsProfile) profile).setSecretKey(view.staticSecretKeyTextField.getText());
                }
                if (view.staticSessionTokenTextField.hasFocus()) {
                    ((StaticCredentialsProfile) profile).setSessionToken(view.staticSessionTokenTextField.getText());
                }
            } else if (profile instanceof CommandProfile) {
                if (view.commandCommandTextField.hasFocus()) {
                    ((CommandProfile) profile).setCommand(view.commandCommandTextField.getText());
                }
                if (view.commandDurationTextField.hasFocus()) {
                    ((CommandProfile) profile).setDurationSecondsFromText(view.commandDurationTextField.getText());
                }
            } else if ( profile instanceof AssumeRoleProfile) {
                if (view.assumeRoleRoleArnTextField.hasFocus()) {
                    ((AssumeRoleProfile) profile).setRoleArn(view.assumeRoleRoleArnTextField.getText());
                }
            }

            //Check if we even have enough information to test this profile
            if (!profile.requiredFieldsAreSet()) {
                logDebug("Profile " + profile.getName() + " does not have all required fields");
                updateProfileStatus();
                return;
            }

            view.profileStatusTextLabel.setText("Starting profile test");

            //Run in another thread to not block the UI
            new Thread(() -> {
                ProfileCredentialTester tester = new ProfileCredentialTester(profile);
                try {
                    SigningCredentials creds = tester.testProfile();

                    logInfo("Successfully obtained credentials with profile: " + profile.getName());

                    //Check if we're still showing the same profile
                    Optional<Profile> newProfileOptional = getCurrentSelectedProfile();
                    if (newProfileOptional.isEmpty()) {
                        logDebug("There is no currently selected profile to test credentials for.");
                        //No profile is currnetly selected 
                    }
                    Profile newProfile = newProfileOptional.get();
                    if (profile.getName().equals(newProfile.getName())) {
                        //Showing the same profile. we can update UI fields. 
                        view.profileStatusTextLabel.setText("Success");
                        if (profile instanceof CommandProfile) {
                            view.commandExtractedAccessKeyTextField.setText(creds.getAccessKey());
                            view.commandExtractedSecretKeyTextField.setText(creds.getSecretKey());
                            if (creds.getSessionToken().isPresent()) {
                                view.commandExtractedSessionTokenTextField.setText(creds.getSessionToken().get());
                            }
                        }
                    }

                } catch (Exception ex) {
                    logError("Failed to obtain credentials with profile: " + profile.getName());

                    //Quick check to see if we need to report the cause at one level deeper
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    logError("Cause: " + cause.getMessage());
                    view.profileStatusTextLabel.putClientProperty("html.disable", null);
                    view.profileStatusTextLabel.setText("<html><b>Error testing profile:</b> " + cause.getMessage() + "</html>");
                }
            }).start();

        }));

        //Static Credentials Access Key text field
        view.staticAccessKeyTextField.addFocusListener(new TextComponentFocusListener<>(this, "Static Credentials Access Key", StaticCredentialsProfile::setAccessKey));

        //Static Credentials Secret Key text field
        view.staticSecretKeyTextField.addFocusListener(new TextComponentFocusListener<>(this, "Static Credentials Secret Key", StaticCredentialsProfile::setSecretKey));

        //Static Credentials Session Token text field
        view.staticSessionTokenTextField.addFocusListener(new TextComponentFocusListener<>(this, "Static Credentials Secret Key", StaticCredentialsProfile::setSessionToken));

        //AssumeRole assumer profile
        assumerProfileComboBoxProfileSelectionListener = new ComboBoxProfileSelectionListener(model, "Always Sign With", (Profile profile) -> {
            //This SHOULD be a safe assumption, but I'm concerned...
            AssumeRoleProfile currentSelectedProfile = (AssumeRoleProfile) getCurrentSelectedProfile().get();
            logDebug("Setting \"Assumer Profile\" Profile of " + currentSelectedProfile.getName() + " to: " + profile);
            currentSelectedProfile.setAssumerProfile(profile);
        });
        view.assumeRoleAssumerProfileComboBox.addItemListener(assumerProfileComboBoxProfileSelectionListener);

        //AssumeRole Role ARN text field
        view.assumeRoleRoleArnTextField.addFocusListener(new TextComponentFocusListener<>(this, "AssumeRole Role ARN", AssumeRoleProfile::setRoleArn));

        //AssumeRole Session Name text field
        view.assumeRoleSessionNameTextField.addFocusListener(new TextComponentFocusListener<>(this, "AssumeRole Session Name", AssumeRoleProfile::setSessionName));

        //AssumeRole External Id text field
        view.assumeRoleExternalIdTextField.addFocusListener(new TextComponentFocusListener<>(this, "AssumeRole External Id", AssumeRoleProfile::setExternalId));

        //AssumeRole Duration text field
        view.assumeRoleDurationTextField.addFocusListener(new TextComponentFocusListener<>(this, "AssumeRole Duration Seconds", AssumeRoleProfile::setDurationSecondsFromText));

        //AssumeRole Session Policy text area
        view.assumeRoleSessionPolicyTextArea.addFocusListener(new TextComponentFocusListener<>(this, "AssumeRole Session Policy", AssumeRoleProfile::setSessionPolicy));

        //AssumeRole Session Policy Prettify Button
        view.assumeRoleSessionPolicyPrettifyButton.addActionListener(((ActionEvent e) -> {
            logDebug("Session Policy Prettify Button Clicked.");
            
            //This SHOULD be a safe assumption, but I'm concerned...
            AssumeRoleProfile currentSelectedProfile = (AssumeRoleProfile) getCurrentSelectedProfile().get();
            Optional<String> sessionPolicyOptional = currentSelectedProfile.getSessionPolicy();

            if (sessionPolicyOptional.isPresent()) {
                String sessionPolicy = sessionPolicyOptional.get();
                try {
                    //Parse the session policy text into JSON
                    JsonObject json = JsonParser.parseString(sessionPolicy).getAsJsonObject();

                    //Back to a string with pretty-printing
                    String prettyJson = new GsonBuilder().setPrettyPrinting().create().toJson(json);

                    //Set both the profile value and the UI field
                    view.assumeRoleSessionPolicyTextArea.setText(prettyJson);
                    currentSelectedProfile.setSessionPolicy(prettyJson);
                } catch (RuntimeException ex) {
                    logError("Unable to parse session policy into JSON object and pretty print. Current value: " + sessionPolicy);
                    //Quick check to see if we need to report the cause at one level deeper
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    view.profileStatusTextLabel.putClientProperty("html.disable", null);
                    view.profileStatusTextLabel.setText("<html><b>Session policy error:</b> " + cause.getMessage() + "</html>");
                }
            } else {
                logDebug("There's no current session policy. Nothing to set.");
            }

        }));

        //Command Duration text field
        view.commandCommandTextField.addFocusListener(new TextComponentFocusListener<>(this, "Command Command", CommandProfile::setCommand));

        //Command Duration text field
        view.commandDurationTextField.addFocusListener(new TextComponentFocusListener<>(this, "Command Duration Seconds", CommandProfile::setDurationSecondsFromText));

        //Add focus handler to various components (panels, etc) to ensure that when the user clicks out of input field, that field loses focus.
        addFocusGrabber(view.globalSettingsPanel);
        addFocusGrabber(view.profileListScrollPane);
        addFocusGrabber(view.rightSideParentPanel);
        addFocusGrabber(view.profileConfigurationPanel);
        addFocusGrabber(view.profileConfigurationScrollPane);
        addFocusGrabber(view.staticCredentialsPanel);
        addFocusGrabber(view.assumeRolePanel);
        addFocusGrabber(view.commandPanel);
        addFocusGrabber(view.commandPanel);

    }

    private void addFocusGrabber(final Component focusable) {

        focusable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                LogWriter.logDebug("Grabbing focus for containing component.");
                focusable.requestFocusInWindow();
            }
        });
    }

    private void handleProfileConfigurationCheckboxEvent(ItemEvent e, String propertyLoggingName, BiConsumer<Profile, Boolean> updateFunction) {
        logDebug("Profile " + propertyLoggingName + " State Change:" + e.getStateChange());
        boolean checkboxEnabled = (e.getStateChange() == ItemEvent.SELECTED);
        Optional<Profile> currentProfileOptional = getCurrentSelectedProfile();
        if (currentProfileOptional.isPresent()) {
            Profile currentProfile = currentProfileOptional.get();
            logInfo("Profile " + currentProfile.getName() + " " + propertyLoggingName + " changed to " + (checkboxEnabled ? "enabled" : "disabled"));
            updateFunction.accept(currentProfile, checkboxEnabled);
        } else {
            logDebug("Profile " + propertyLoggingName + " changed, but no profile selected. Ignoring.");
        }
        updateProfileStatus();
    }

    private void addProfile(Profile newProfile) {
        //Add it to our model for tracking
        model.profiles.add(newProfile);

        //Setup profile list
        DefaultListModel listModel = resetProfileList();
        view.profileList.setSelectedIndex(listModel.indexOf(newProfile.getName()));

        //Reset "Always Sign With" combo box
        resetAlwaysSignWithProfileComboBox();

        initializeProfileConfigurationTab(newProfile);
    }

    private void deleteProfile(Profile profile) {
        //Confirm our model contains the profile. This is just a sanity check
        if (!model.profiles.contains(profile)) {
            logError("Attempting to delete profile which doesn't exist. Something is wrong!");
            return;
        }
        logDebug("Removing " + profile.getName());

        //TODO: Need to handle 2 main cases.     
        if (model.profiles.size() == 1) {
            //1. We're removing the only model, reset to initial view
            logDebug("Removing only profile. Resetting to initial display");
            model.profiles.remove(profile);
            resetProfileList();
            resetAlwaysSignWithProfileComboBox();
            resetProfileConfigurationTabToDefault();
        } else {
            //2. There is at least one other profile. Select the next one. 
            logDebug("Removing profile and selecting the next in line.");

            //Determine which profile will be shown next.
            DefaultListModel listModel = resetProfileList();
            int indexToBeDeleted = listModel.indexOf(profile.getName());
            //if we're at the bottom, select one up, otherwise select one profile down
            int nextSelectionIndex;
            if (indexToBeDeleted == listModel.size() - 1) {
                nextSelectionIndex = indexToBeDeleted - 1;
            } else {
                nextSelectionIndex = indexToBeDeleted + 1;
            }
            String nextProfileName = (String) listModel.get(nextSelectionIndex);

            //OK now remove it
            model.profiles.remove(profile);
            resetProfileList();
            resetAlwaysSignWithProfileComboBox();

            //Select and display the next choice.
            listModel = resetProfileList();
            Profile selectedProfile = model.getProfileForName(nextProfileName).get();
            view.profileList.setSelectedIndex(listModel.indexOf(nextProfileName));
            initializeProfileConfigurationTab(selectedProfile);
        }

    }

    private void initializeProfileConfigurationTab(Profile currentProfile) {
        initializeProfileConfigurationCommonFields(currentProfile);

        //Handle type-specific fields
        if (currentProfile instanceof StaticCredentialsProfile) {
            StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) currentProfile;
            initializeStaticCredentialsProfileFields(staticCredentialsProfile);
            ((CardLayout) view.credentialCardContainerPanel.getLayout()).show(view.credentialCardContainerPanel, "static_credentials_card");
        } else if (currentProfile instanceof AssumeRoleProfile) {
            AssumeRoleProfile assumeRoleProfile = (AssumeRoleProfile) currentProfile;
            initializeAssumeRoleProfileFields(assumeRoleProfile);
            ((CardLayout) view.credentialCardContainerPanel.getLayout()).show(view.credentialCardContainerPanel, "assume_role_card");
        } else if (currentProfile instanceof CommandProfile) {
            CommandProfile commandProfile = (CommandProfile) currentProfile;
            initializeCommandProfileFields(commandProfile);
            ((CardLayout) view.credentialCardContainerPanel.getLayout()).show(view.credentialCardContainerPanel, "command_card");
        } else {
            throw new IllegalStateException("Profile does not match expected type. Found Type: " + currentProfile.getClass().getName());
        }

        //Update the profile's status:
        updateProfileStatus();
    }

    private void resetProfileConfigurationTabToDefault() {
        //Reset the "common" fields
        view.profileNameLabel.setText("[Add A Profile To Begin]");
        view.profileEnabledCheckbox.setEnabled(false);
        view.profileEnabledCheckbox.setSelected(false);
        view.profileInScopeOnlyCheckbox.setEnabled(false);
        view.profileInScopeOnlyCheckbox.setSelected(false);
        view.profileRegionTextField.setEnabled(false);
        view.profileRegionTextField.setText("");
        view.profileServiceTextField.setEnabled(false);
        view.profileServiceTextField.setText("");
        view.profileKeyIdTextField.setEnabled(false);
        view.profileKeyIdTextField.setText("");
        view.testProfileButton.setEnabled(false);

        //Default to the static creds card
        ((CardLayout) view.credentialCardContainerPanel.getLayout()).show(view.credentialCardContainerPanel, "static_credentials_card");
        view.staticAccessKeyTextField.setEnabled(false);
        view.staticAccessKeyTextField.setText("");
        view.staticAccessKeyTextField.getInputVerifier().shouldYieldFocus(view.staticAccessKeyTextField, view.staticAccessKeyTextField);
        view.staticSecretKeyTextField.setEnabled(false);
        view.staticSecretKeyTextField.setText("");
        view.staticSecretKeyTextField.getInputVerifier().shouldYieldFocus(view.staticSecretKeyTextField, view.staticSecretKeyTextField);
        view.staticSessionTokenTextField.setEnabled(false);
        view.staticSessionTokenTextField.setText("");
        view.profileStatusTextLabel.setText("Must add profile to begin editing");

    }

    private void initializeProfileConfigurationCommonFields(Profile currentProfile) {
        //Update the Profile Configuration Tab common fields
        view.profileNameLabel.setText(currentProfile.getName());
        view.profileEnabledCheckbox.setEnabled(true);
        view.profileEnabledCheckbox.setSelected(currentProfile.isEnabled());
        view.profileInScopeOnlyCheckbox.setEnabled(true);
        view.profileInScopeOnlyCheckbox.setSelected(currentProfile.isInScopeOnly());
        view.profileRegionTextField.setEnabled(true);
        view.profileRegionTextField.setText(currentProfile.getRegion().orElse(""));
        view.profileServiceTextField.setEnabled(true);
        view.profileServiceTextField.setText(currentProfile.getService().orElse(""));
        view.profileKeyIdTextField.setEnabled(true);
        view.profileKeyIdTextField.setText(currentProfile.getKeyId().orElse(""));
        view.testProfileButton.setEnabled(true);
    }

    private void initializeStaticCredentialsProfileFields(StaticCredentialsProfile staticCredentialsProfile) {
        String accessKey = staticCredentialsProfile.getAccessKey().orElse("");
        String secretKey = staticCredentialsProfile.getSecretKey().orElse("");
        String sessionToken = staticCredentialsProfile.getSessionToken().orElse("");

        view.staticAccessKeyTextField.setEnabled(true);
        view.staticAccessKeyTextField.setText(accessKey);
        view.staticAccessKeyTextField.getInputVerifier().shouldYieldFocus(view.staticAccessKeyTextField, view.staticAccessKeyTextField);
        view.staticSecretKeyTextField.setEnabled(true);
        view.staticSecretKeyTextField.setText(secretKey);
        view.staticSecretKeyTextField.getInputVerifier().shouldYieldFocus(view.staticSecretKeyTextField, view.staticSecretKeyTextField);
        view.staticSessionTokenTextField.setEnabled(true);
        view.staticSessionTokenTextField.setText(sessionToken);

        //Calculate initial status
        if ((accessKey == null) && (secretKey == null)) {
            view.profileStatusTextLabel.setText("Missing Access Key and Secret Key");
        } else if ((accessKey == null)) {
            view.profileStatusTextLabel.setText("Missing Access Key");
        } else if ((secretKey == null)) {
            view.profileStatusTextLabel.setText("Missing Secret Key");
        } else {
            view.profileStatusTextLabel.setText("Ready for testing");
        }
    }

    private void initializeAssumeRoleProfileFields(AssumeRoleProfile assumeRoleProfile) {

        //Calculate which profiles may be used as the assumer
        List<Profile> profiles = model.profiles;
        List<String> profileNames = profiles.stream()
                .filter(profile -> {
                    final String potentialAssumerProfileName = profile.getName();
                    logDebug("Checking if profile should be included in assumer profile choices: " + potentialAssumerProfileName);
                    //Check if the potential profile is the profile being shown. 
                    //AssumeRole can't use itself as the assumer
                    if (potentialAssumerProfileName.equals(assumeRoleProfile.getName())) {
                        logDebug("Excluding self from assumer profile choices: " + potentialAssumerProfileName);
                        return false;
                    }

                    //This loop prevents a cycle of assume role. Walk up the chain
                    // of assumer profiles and confirm the current profile isn't present
                    // in that chain.
                    Profile potentialAssumer = profile;
                    while (potentialAssumer instanceof AssumeRoleProfile) {

                        //This is an assume role profile itself.
                        Optional<Profile> parentAssumerProfileOptional = ((AssumeRoleProfile) potentialAssumer).getAssumerProfile();
                        //Check if the parent is set.
                        if (parentAssumerProfileOptional.isPresent()) {
                            Profile parentAssumerProfile = parentAssumerProfileOptional.get();
                            //Make sure the parent assumer profile is not the same one being configured. That would be a cycle.
                            if (parentAssumerProfile.getName().equals(assumeRoleProfile.getName())) {
                                logDebug("Excluding "
                                        + potentialAssumerProfileName
                                        + " from being an assumer profile for "
                                        + assumeRoleProfile.getName()
                                        + " because it would create a cycle through the "
                                        + potentialAssumer.getName() + " profile.");
                                return false;
                            }
                            //Loop again to go up another level
                            potentialAssumer = parentAssumerProfile;
                        } else {
                            //The parent isn't set. Safe to break out and include
                            break;
                        }
                    }
                    //If we made it here, no cycle detected. This profile can be an assumer 
                    logDebug("Including profile in assumer profile choices: " + potentialAssumerProfileName);
                    return true;
                })
                .map(Profile::getName)
                .collect(Collectors.toList());

        //Setup the assumer profile combobox
        view.assumeRoleAssumerProfileComboBox.removeItemListener(assumerProfileComboBoxProfileSelectionListener);
        view.assumeRoleAssumerProfileComboBox.removeAllItems();
        view.assumeRoleAssumerProfileComboBox.addItem(""); //Add a blank
        profileNames.forEach((name) -> {
            view.assumeRoleAssumerProfileComboBox.addItem(name);
        });

        if (assumeRoleProfile.getAssumerProfile().isPresent()) {
            String parentAssumerProfileName = assumeRoleProfile.getAssumerProfile().get().getName();
            logDebug("Setting selected assumer profile to: " + parentAssumerProfileName);
            view.assumeRoleAssumerProfileComboBox.setSelectedItem(parentAssumerProfileName);
        }
        view.assumeRoleAssumerProfileComboBox.addItemListener(assumerProfileComboBoxProfileSelectionListener);

        view.assumeRoleRoleArnTextField.setText(assumeRoleProfile.getRoleArn().orElse(null));
        view.assumeRoleRoleArnTextField.getInputVerifier().shouldYieldFocus(view.assumeRoleRoleArnTextField, view.assumeRoleRoleArnTextField);
        view.assumeRoleSessionNameTextField.setText(assumeRoleProfile.getSessionName().orElse(null));
        view.assumeRoleExternalIdTextField.setText(assumeRoleProfile.getExternalId().orElse(null));
        if (assumeRoleProfile.getDurationSeconds().isEmpty()) {
            view.assumeRoleDurationTextField.setText(null);
        } else {
            view.assumeRoleDurationTextField.setText(Integer.toString(assumeRoleProfile.getDurationSeconds().get()));
        }
        view.assumeRoleDurationTextField.getInputVerifier().shouldYieldFocus(view.assumeRoleDurationTextField, view.assumeRoleDurationTextField);
        view.assumeRoleSessionPolicyTextArea.setText(assumeRoleProfile.getSessionPolicy().orElse(null));

    }

    private void initializeCommandProfileFields(CommandProfile commandProfile) {
        String command = commandProfile.getCommand().orElse("");
        Optional<Integer> durationSeconds = commandProfile.getDurationSeconds();
        view.commandCommandTextField.setText(command);
        view.commandCommandTextField.getInputVerifier().shouldYieldFocus(view.commandCommandTextField, view.commandCommandTextField);
        if (durationSeconds.isEmpty()) {
            view.commandDurationTextField.setText(null);
        } else {
            view.commandDurationTextField.setText(Integer.toString(durationSeconds.get()));
        }
        view.commandExtractedAccessKeyTextField.setText("");
        view.commandExtractedSecretKeyTextField.setText("");
        view.commandExtractedSessionTokenTextField.setText("");
    }

    void updateProfileStatus() {
        Optional<Profile> currentProfileOptional = getCurrentSelectedProfile();
        String status = "Unknown";
        if (currentProfileOptional.isPresent()) {
            Profile currentProfile = currentProfileOptional.get();
            //Handle type-specific status calculation
            if (currentProfile instanceof StaticCredentialsProfile) {
                StaticCredentialsProfile staticCredentialsProfile = (StaticCredentialsProfile) currentProfile;
                if (staticCredentialsProfile.getAccessKey().isEmpty() && staticCredentialsProfile.getSecretKey().isEmpty()) {
                    status = "Missing Access Key and Secret Key";
                } else if (staticCredentialsProfile.getAccessKey().isEmpty()) {
                    status = "Missing Access Key";
                } else if (staticCredentialsProfile.getSecretKey().isEmpty()) {
                    status = "Missing Secret Key";
                } else {
                    status = "Ready for testing";
                }
            } else if (currentProfile instanceof AssumeRoleProfile) {
                AssumeRoleProfile assumeRoleProfile = (AssumeRoleProfile) currentProfile;
                Optional<Profile> assumerProfile = assumeRoleProfile.getAssumerProfile();
                Optional<String> roleArn = assumeRoleProfile.getRoleArn();
                if (assumerProfile.isEmpty() && roleArn.isEmpty()) {
                    status = "Missing Assumer Profile and Role ARN";
                } else if (assumerProfile.isEmpty()) {
                    status = "Missing Assumer Profile";
                } else if (roleArn.isEmpty()) {
                    status = "Missing Role ARN";
                } else {
                    status = "Ready for testing";
                }
            } else if (currentProfile instanceof CommandProfile) {
                CommandProfile commandProfile = (CommandProfile) currentProfile;
                if (commandProfile.getCommand().isEmpty()) {
                    status = "Missing Command";
                } else {
                    status = "Ready for testing";
                }
            } else {
                final String errorMessage = "Profile does not match expected type. Found Type: " + currentProfile.getClass().getName();
                logError(errorMessage);
                throw new IllegalStateException(errorMessage);
            }
        }

        logDebug("Profile status set as: " + status);
        view.profileStatusTextLabel.setText(status);
    }

    private DefaultListModel resetProfileList() {
        //Update our URI to track
        //Reset the profile list
        DefaultListModel listModel = new DefaultListModel();
        List<String> profileNames = model.getProfileNames();
        listModel.addAll(profileNames);
        view.profileList.setModel(listModel);
        return listModel;
    }

    private void resetAlwaysSignWithProfileComboBox() {
        view.alwaysSignWithProfileComboBox.removeItemListener(alwaysSignWithComboBoxProfileSelectionListener);
        List<String> profileNames = model.getProfileNames();
        view.alwaysSignWithProfileComboBox.removeAllItems();
        view.alwaysSignWithProfileComboBox.addItem(" "); //Add a blank
        profileNames.forEach((name) -> {
            view.alwaysSignWithProfileComboBox.addItem(name);
        });
        if (model.alwaysSignWithProfile != null) {
            view.alwaysSignWithProfileComboBox.setSelectedItem(model.alwaysSignWithProfile.getName());
        }
        view.alwaysSignWithProfileComboBox.addItemListener(alwaysSignWithComboBoxProfileSelectionListener);
    }

    public Optional<Profile> getCurrentSelectedProfile() {
        String selectedProfileName = view.profileList.getSelectedValue();
        return model.getProfileForName(selectedProfileName);
    }

    public List<JMenuItem> getMenuItems(IContextMenuInvocation invocation) {
        JMenu menu = new JMenu(BurpExtender.EXTENSION_NAME);

        //Enable/Disable global signing sub menu
        JMenu signerEnableSubmenu = new JMenu("Enable/Disable Signing");
        ButtonGroup signerEnableGroup = new ButtonGroup();
        JRadioButtonMenuItem enableSigningMenuItem = new JRadioButtonMenuItem("Enable Signing", model.isEnabled);
        enableSigningMenuItem.addActionListener((event) -> {
            logDebug("Signing enabled via context menu");
            model.isEnabled = true;
            view.signingEnabledCheckbox.setSelected(true);
        });
        signerEnableGroup.add(enableSigningMenuItem);
        signerEnableSubmenu.add(enableSigningMenuItem);
        JRadioButtonMenuItem disableSigningMenuItem = new JRadioButtonMenuItem("Disable Signing", !model.isEnabled);
        disableSigningMenuItem.addActionListener((event) -> {
            logDebug("Signing disabled via context menu");
            model.isEnabled = false;
            view.signingEnabledCheckbox.setSelected(false);
        });
        signerEnableGroup.add(disableSigningMenuItem);
        signerEnableSubmenu.add(disableSigningMenuItem);
        menu.add(signerEnableSubmenu);

        //Set Default Profile
        JMenu defaultProfileSubmenu = new JMenu("Set \"Always Sign With\" Profile");
        ButtonGroup defaultProfileGroup = new ButtonGroup();

        //The first profile is special since it represents NOT having a default profile
        JRadioButtonMenuItem noDefaultProfileItem = new JRadioButtonMenuItem("<html><i>No Profile</i></html>", model.alwaysSignWithProfile == null);
        noDefaultProfileItem.putClientProperty("html.disable", null);
        noDefaultProfileItem.addActionListener((event) -> {
            logDebug("Always sign with profile unset via context menu");
            model.alwaysSignWithProfile = null;
            resetAlwaysSignWithProfileComboBox();
        });
        defaultProfileGroup.add(noDefaultProfileItem);
        defaultProfileSubmenu.add(noDefaultProfileItem);

        List<Profile> profileList = model.profiles;
        for (Profile profile : profileList) {
            JRadioButtonMenuItem profileItem = new JRadioButtonMenuItem(profile.getName(), model.alwaysSignWithProfile != null && model.alwaysSignWithProfile.getName().equals(profile.getName()));
            profileItem.addActionListener((event) -> {
                logDebug("Default profile set via context menu. Chosen profile: " + profile.getName());
                model.alwaysSignWithProfile = profile;
                resetAlwaysSignWithProfileComboBox();
            });
            defaultProfileGroup.add(profileItem);
            defaultProfileSubmenu.add(profileItem);
        }
        menu.add(defaultProfileSubmenu);

        List<JMenuItem> list = new ArrayList<>();
        list.add(menu);
        return list;
    }

}
