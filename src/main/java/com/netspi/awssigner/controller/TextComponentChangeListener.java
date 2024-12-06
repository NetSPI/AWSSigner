package com.netspi.awssigner.controller;

import static com.netspi.awssigner.log.LogWriter.*;
import com.netspi.awssigner.model.Profile;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Optional;
import java.util.function.BiConsumer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;

class TextComponentChangeListener<T extends Profile> implements FocusListener, DocumentListener {

    private final AWSSignerController controller;
    private final JTextComponent textComponent;
    private final String propertyLoggingName;
    private final BiConsumer<T, String> updateFunction;
    private String previousValue = "";

    public TextComponentChangeListener(AWSSignerController controller, JTextComponent textComponent, String propertyLoggingName, BiConsumer<T, String> updateFunction) {
        this.controller = controller;
        this.textComponent = textComponent;
        this.propertyLoggingName = propertyLoggingName;
        this.updateFunction = updateFunction;

        // Initialize previousValue and add listeners once
        this.previousValue = textComponent.getText();
        this.textComponent.addFocusListener(this);
        this.textComponent.getDocument().addDocumentListener(this);
    }

    @Override
    public void focusGained(FocusEvent e) {
        previousValue = textComponent.getText(); // Update previous value on focus gain
        logDebug("Profile " + propertyLoggingName + " Text Field focus gained. Cause: " + e.getCause() + " ID:" + e.getID() + " Current value: " + previousValue);
    }

    @Override
    public void focusLost(FocusEvent e) {
        logDebug("Profile " + propertyLoggingName + " Text Field focus lost. Cause: " + e.getCause() + " ID:" + e.getID());
        String currentText = textComponent.getText();
        if (!previousValue.equals(currentText)) {
            updateProfile(currentText);
        }
    }

    // DocumentListener methods
    @Override
    public void insertUpdate(DocumentEvent e) {
        textChanged();
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        textChanged();
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        // Typically not used for plain text components
    }

    private void textChanged() {
        String currentText = textComponent.getText();
        if (!previousValue.equals(currentText)) {
            previousValue = currentText;
            updateProfile(currentText);
        }
    }

    private void updateProfile(String currentText) {
        Optional<Profile> currentProfileOptional = controller.getCurrentSelectedProfile();
        if (currentProfileOptional.isPresent()) {
            Profile currentProfile = currentProfileOptional.get();
            try {
                @SuppressWarnings("unchecked")
                T profile = (T) currentProfile;
                logInfo("Profile " + currentProfile.getName() + " " + propertyLoggingName + " text changed. New Value: " + currentText);
                updateFunction.accept(profile, currentText);
                controller.updateProfileStatus();
            } catch (ClassCastException e) {
                logError("Type mismatch: Cannot cast " + currentProfile.getClass().getName() + " to the expected type.");
            }
        } else {
            logDebug("Profile " + propertyLoggingName + " changed, but no profile selected. Ignoring.");
        }
    }
}