package com.netspi.awssigner.controller;
 
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netspi.awssigner.credentials.ProfileCredentialTester;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.netspi.awssigner.log.LogLevel;
import com.netspi.awssigner.log.LogWriter;
import static com.netspi.awssigner.log.LogWriter.logDebug;
import static com.netspi.awssigner.log.LogWriter.logError;
import static com.netspi.awssigner.log.LogWriter.logInfo;
import com.netspi.awssigner.model.AWSSignerConfiguration;
import com.netspi.awssigner.model.AssumeRoleProfile;
import com.netspi.awssigner.model.CommandProfile;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import com.netspi.awssigner.model.persistence.ProfileExporter;
import com.netspi.awssigner.view.AddProfileDialog;
import com.netspi.awssigner.view.BurpTabPanel;
import com.netspi.awssigner.view.BurpUIComponentCustomizer;
import com.netspi.awssigner.view.CopyProfileDialog;
import com.netspi.awssigner.view.ImportDialog;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.MouseAdapter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.text.Document;
import javax.swing.text.AbstractDocument;
import javax.swing.text.BadLocationException;
 
 
 
/**
 * The controller class which enforces logic and syncs up the configuration model
 * and the UI view. This class coordinates between the UI (view), the configuration model,
 * and the credentials logic.
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
 
        //Add the initial profile
        addProfile(new StaticCredentialsProfile(INIT_PROFILE_NAME));
    }
 
    private void initListeners() {
        //Global signing checkbox
        view.signingEnabledCheckbox.addItemListener((ItemEvent e) -> {
            logDebug("Global Signing Enabled Checkbox State Change.");
            model.isEnabled = (e.getStateChange() == ItemEvent.SELECTED);
            logInfo("Signing Enabled: " + model.isEnabled);
        });
 
        //"Always Sign With" profile selection combo box
        alwaysSignWithComboBoxProfileSelectionListener = new ComboBoxProfileSelectionListener(model, "Always Sign With", (Profile profile) -> {
            logDebug("Setting \"Always Sign With\" Profile to: " + profile);
            model.alwaysSignWithProfile = profile;
        });
        view.alwaysSignWithProfileComboBox.addItemListener(alwaysSignWithComboBoxProfileSelectionListener);
 
        //Logging Level combo box
        view.logLevelComboBox.addItemListener(((event) -> {
            logDebug("Log Level ComboBox Item Event:" + " StateChange: " + event.getStateChange() + " Item: " + event.getItem());
            if (event.getStateChange() == ItemEvent.SELECTED) {
                String selectedLoggingLevel = (String) event.getItem();
                LogLevel newLoggingLevel = LogLevel.valueOf(selectedLoggingLevel.toUpperCase());
                logDebug("New logging level set to: " + newLoggingLevel);
                LogWriter.setLevel(newLoggingLevel);
            }
        }));
 
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
            if (optionalCurrentProfile.isPresent()) {
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
            } else {
                logInfo("No currently selected profile to copy.");
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
                importedProfiles.forEach(this::addProfile);
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
        new TextChangeHandler(
            view.profileRegionTextField,
            "Region",
            createProfileFieldConsumer("Region", Profile::setRegion)
        );
 
        //Profile Service text field
        new TextChangeHandler(
            view.profileServiceTextField,
            "Service",
            createProfileFieldConsumer("Service", Profile::setService)
        );
 
        //Profile Key Id text field
        new TextChangeHandler(
            view.profileKeyIdTextField,
            "Key Id",
            createProfileFieldConsumer("Key Id", Profile::setKeyId)
        );
 
        //Test credentials button
        view.testProfileButton.addActionListener(((ActionEvent e) -> {
            logDebug("Test Credentials Button Clicked.");
 
            Optional<Profile> currentProfileOptional = getCurrentSelectedProfile();
            if (currentProfileOptional.isEmpty()) {
                logDebug("There is no currently selected profile to test credentials for.");
                return;
            }
 
            Profile profile = currentProfileOptional.get();
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
                        logDebug("No currently selected profile after test.");
                        return;
                    }
                    Profile newProfile = newProfileOptional.get();
                    if (profile.getName().equals(newProfile.getName())) {
                        //Showing the same profile. We can update UI fields. 
                        view.profileStatusTextLabel.setText("Success");
                        if (profile instanceof CommandProfile) {
                            view.commandExtractedAccessKeyTextField.setText(creds.getAccessKey());
                            view.commandExtractedSecretKeyTextField.setText(creds.getSecretKey());
                            creds.getSessionToken().ifPresent(token -> 
                                view.commandExtractedSessionTokenTextField.setText(token)
                            );
                        }
                    }
                } catch (Exception ex) {
                    logError("Failed to obtain credentials with profile: " + profile.getName());
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    logError("Cause: " + cause.getMessage());
                    view.profileStatusTextLabel.putClientProperty("html.disable", null);
                    view.profileStatusTextLabel.setText("<html><b>Error testing profile:</b> " + cause.getMessage() + "</html>");
                }
            }).start();
        }));
 
        // Static Credentials Access Key text field
        new TextChangeHandler(
            view.staticAccessKeyTextField,
            "Static Credentials Access Key",
            createProfileFieldConsumer("Static Credentials Access Key", (profile, newValue) -> {
                ((StaticCredentialsProfile) profile).setAccessKey(newValue);
            })
        );
 
        // Static Credentials Secret Key text field
        new TextChangeHandler(
            view.staticSecretKeyTextField,
            "Static Credentials Secret Key",
            createProfileFieldConsumer("Static Credentials Secret Key", (profile, newValue) -> {
                ((StaticCredentialsProfile) profile).setSecretKey(newValue);
            })
        );
 
        // Static Credentials Session Token text field
        new TextChangeHandler(
            view.staticSessionTokenTextField,
            "Static Credentials Session Token",
            createProfileFieldConsumer("Static Credentials Session Token", (profile, newValue) -> {
                ((StaticCredentialsProfile) profile).setSessionToken(newValue);
            })
        );
 
        //AssumeRole assumer profile combo box
        assumerProfileComboBoxProfileSelectionListener = new ComboBoxProfileSelectionListener(model, "Always Sign With", (Profile profile) -> {
            AssumeRoleProfile currentSelectedProfile = (AssumeRoleProfile) getCurrentSelectedProfile().get();
            logDebug("Setting \"Assumer Profile\" Profile of " + currentSelectedProfile.getName() + " to: " + profile);
            currentSelectedProfile.setAssumerProfile(profile);
        });
        view.assumeRoleAssumerProfileComboBox.addItemListener(assumerProfileComboBoxProfileSelectionListener);
 
        // AssumeRole Role ARN text field
        new TextChangeHandler(
            view.assumeRoleRoleArnTextField,
            "AssumeRole Role ARN",
            createProfileFieldConsumer("AssumeRole Role ARN", (profile, newValue) -> {
                ((AssumeRoleProfile) profile).setRoleArn(newValue);
            })
        );
 
        // AssumeRole Session Name text field
        new TextChangeHandler(
            view.assumeRoleSessionNameTextField,
            "AssumeRole Session Name",
            createProfileFieldConsumer("AssumeRole Session Name", (profile, newValue) -> {
                ((AssumeRoleProfile) profile).setSessionName(newValue);
            })
        );
 
        // AssumeRole External Id text field
        new TextChangeHandler(
            view.assumeRoleExternalIdTextField,
            "AssumeRole External Id",
            createProfileFieldConsumer("AssumeRole External Id", (profile, newValue) -> {
                ((AssumeRoleProfile) profile).setExternalId(newValue);
            })
        );
 
        // AssumeRole Duration text field
        new TextChangeHandler(
            view.assumeRoleDurationTextField,
            "AssumeRole Duration Seconds",
            createProfileFieldConsumer("AssumeRole Duration Seconds", (profile, newValue) -> {
                ((AssumeRoleProfile) profile).setDurationSecondsFromText(newValue);
            })
        );
 
        // AssumeRole Session Policy text area
        new TextChangeHandler(
            view.assumeRoleSessionPolicyTextArea,
            "AssumeRole Session Policy",
            createProfileFieldConsumer("AssumeRole Session Policy", (profile, newValue) -> {
                ((AssumeRoleProfile) profile).setSessionPolicy(newValue);
            })
        );
 
        // Add Undo/Redo support to the text areas where appropriate (for example, AssumeRole session policy)
        new TextUndoRedoSupport(view.assumeRoleSessionPolicyTextArea);
 
        // Setup regex highlighter for the session policy text area
        RegexHighlighter regexHighlighter = new RegexHighlighter(view.assumeRoleSessionPolicyTextArea);
 
        //AssumeRole Session Policy Prettify Button
        view.assumeRoleSessionPolicyPrettifyButton.addActionListener(((ActionEvent e) -> {
            logDebug("Session Policy Prettify Button Clicked.");
            AssumeRoleProfile currentSelectedProfile = (AssumeRoleProfile) getCurrentSelectedProfile().get();
            Optional<String> sessionPolicyOptional = currentSelectedProfile.getSessionPolicy();
 
            if (sessionPolicyOptional.isPresent()) {
                String sessionPolicy = sessionPolicyOptional.get();
                try {
                    //Parse the session policy text into JSON
                    JsonObject json = JsonParser.parseString(sessionPolicy).getAsJsonObject();
                    String prettyJson = new GsonBuilder().setPrettyPrinting().create().toJson(json);
 
                    //Set the UI. This should be a single, atomic change to preserve undo/redo behavior
                    Document doc = view.assumeRoleSessionPolicyTextArea.getDocument();
                    if (doc instanceof AbstractDocument) {
                        AbstractDocument aDoc = (AbstractDocument) doc;
                        aDoc.replace(0, aDoc.getLength(), prettyJson, null);
                    } else {
                        // Fallback if not an AbstractDocument, though typically JTextArea uses PlainDocument which is an AbstractDocument.
                        view.assumeRoleSessionPolicyTextArea.setText(prettyJson);
                    }
 
                    //Set the profile value
                    currentSelectedProfile.setSessionPolicy(prettyJson);
                    logDebug("Session policy prettified successfully.");
                } catch (RuntimeException | BadLocationException ex) {
                    logError("Unable to parse session policy into JSON object or update text area. Current value: " + sessionPolicy);
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    view.profileStatusTextLabel.putClientProperty("html.disable", null);
                    view.profileStatusTextLabel.setText("<html><b>Session policy error:</b> " + cause.getMessage() + "</html>");
                }
            } else {
                logDebug("There's no current session policy. Nothing to set.");
            }
        }));
 
        // AssumeRole Session Policy Find Button
        view.assumeRoleSessionPolicyFindButton.addActionListener(e -> {
            String regex = view.assumeRoleSessionPolicyRegexField.getText().trim();
            try {
                regexHighlighter.findAndHighlightNext(regex);
            } catch (PatternSyntaxException ex) {
                logError("Invalid regex: " + ex.getMessage());
            }
        });
 
        // AssumeRole Session Policy Replace Button
        view.assumeRoleSessionPolicyReplaceButton.addActionListener(e -> {
            String replacement = view.assumeRoleSessionPolicyReplacementField.getText();
            regexHighlighter.replaceCurrentMatch(replacement);
        });
 
        // AssumeRole Session Policy Replace All Button
        view.assumeRoleSessionPolicyReplaceAllButton.addActionListener(e -> {
            String replacement = view.assumeRoleSessionPolicyReplacementField.getText();
            regexHighlighter.replaceAllMatches(replacement);
        });
 
        // Command Command text field
        new TextChangeHandler(
            view.commandCommandTextField,
            "Command Command",
            createProfileFieldConsumer("Command Command", (profile, newValue) -> {
                ((CommandProfile) profile).setCommand(newValue);
            })
        );
 
        // Command Duration text field
        new TextChangeHandler(
            view.commandDurationTextField,
            "Command Duration Seconds",
            createProfileFieldConsumer("Command Duration Seconds", (profile, newValue) -> {
                ((CommandProfile) profile).setDurationSecondsFromText(newValue);
            })
        );
 
        //Add focus handler to grab focus for containers
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
 
 
    /**
     * A helper method to avoid repeating similar code for updating profile fields.
     * This method returns a Consumer<String> that:
     * - Fetches the current selected profile
     * - Logs the change
     * - Updates the profile using the provided updateFunction
     * - Updates the profile status
     *
     * @param propertyLoggingName A name of the property for logging.
     * @param updateFunction A BiConsumer that takes the Profile and new String value and updates the profile.
     * @return A Consumer<String> to be used as the onTextChanged callback in TextComponentChangeListener.
     */
    private Consumer<String> createProfileFieldConsumer(String propertyLoggingName, BiConsumer<Profile, String> updateFunction) {
        return (newValue) -> {
            Optional<Profile> currentProfileOptional = getCurrentSelectedProfile();
            if (currentProfileOptional.isPresent()) {
                Profile currentProfile = currentProfileOptional.get();
                logInfo("Profile " + currentProfile.getName() + " " + propertyLoggingName + " text changed. New Value: " + newValue);
                updateFunction.accept(currentProfile, newValue);
                updateProfileStatus();
            } else {
                logDebug(propertyLoggingName + " changed, but no profile selected. Ignoring.");
            }
        };
    }
 
    private void addFocusGrabber(final Component focusable) {
        focusable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
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
        //Confirm our model contains the profile
        if (!model.profiles.contains(profile)) {
            logError("Attempting to delete profile which doesn't exist. Something is wrong!");
            return;
        }
        logDebug("Removing " + profile.getName());
 
        if (model.profiles.size() == 1) {
            //If there's only one profile
            logDebug("Removing only profile. Resetting to initial display");
            model.profiles.remove(profile);
            resetProfileList();
            resetAlwaysSignWithProfileComboBox();
            resetProfileConfigurationTabToDefault();
        } else {
            //There is at least one other profile. Select the next one. 
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
        if ((accessKey.isEmpty()) && (secretKey.isEmpty())) {
            view.profileStatusTextLabel.setText("Missing Access Key and Secret Key");
        } else if ((accessKey.isEmpty())) {
            view.profileStatusTextLabel.setText("Missing Access Key");
        } else if ((secretKey.isEmpty())) {
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
 
        //Existing profiles
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