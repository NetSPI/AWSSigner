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

class TextComponentFocusListener<T extends Profile> implements FocusListener {

    private final AWSSignerController controller;
    private final String propertyLoggingName;
    private final BiConsumer<T, String> updateFunction;
    private Optional<Profile> currentProfileOptional;
    private String currentValue = "";

    public TextComponentFocusListener(AWSSignerController controller, String propertyLoggingName, BiConsumer<T, String> updateFunction) {
        this.controller = controller;
        this.propertyLoggingName = propertyLoggingName;
        this.updateFunction = updateFunction;
    }

    @Override
    public void focusGained(FocusEvent e) {
        currentProfileOptional = controller.getCurrentSelectedProfile();
        JTextComponent textComponent = (JTextComponent) e.getComponent();
        currentValue = textComponent.getText();
        
        // Add document listener when focus is gained
        textComponent.getDocument().addDocumentListener(new DocumentListener() {
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
                textChanged();
            }

            private void textChanged() {
                String currentText = textComponent.getText();
                if (!currentValue.equals(currentText)) {
                    currentValue = currentText;
                    updateProfile(currentText);
                }
            }
        });

        logDebug("Profile " + propertyLoggingName + " Text Field focus gained." + " Cause: " + e.getCause() + " ID:" + e.getID() + " Current value: " + currentValue);
    }

    @Override
    public void focusLost(FocusEvent e) {
        logDebug("Profile " + propertyLoggingName + " Text Field focus lost." + " Cause: " + e.getCause() + " ID:" + e.getID());
        String currentText = ((JTextComponent) e.getComponent()).getText();
        if (!currentValue.equals(currentText)) {
            updateProfile(currentText);
        }
    }

    private void updateProfile(String currentText) {
        if (currentProfileOptional.isPresent()) {
            Profile currentProfile = currentProfileOptional.get();
            logInfo("Profile " + currentProfile.getName() + " " + propertyLoggingName + " text changed. New Value: " + currentText);
            updateFunction.accept((T) currentProfile, currentText);
            controller.updateProfileStatus();
        } else {
            logDebug("Profile " + propertyLoggingName + " focus lost, but no profile selected. Ignoring.");
        }
    }
}