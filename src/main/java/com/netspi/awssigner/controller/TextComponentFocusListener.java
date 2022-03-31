package com.netspi.awssigner.controller;

import static com.netspi.awssigner.log.LogWriter.*;
import com.netspi.awssigner.model.Profile;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Optional;
import java.util.function.BiConsumer;
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
        /*
         * Save the current profile being updated.
         * This is important because we can't just use the SELECTED profile when
         * focus is lost. This fails if focus is lost by selecting a new profile.
         * THAT other newly selected profile would be updated instead
         */
        currentProfileOptional = controller.getCurrentSelectedProfile();

        //Also note the value when focus was gained. This helps us detected if the value actually changed or not when focus is lost
        currentValue = ((JTextComponent) e.getComponent()).getText();

        logDebug("Profile " + propertyLoggingName + " Text Field focus gained." + " Cause: " + e.getCause() + " ID:" + e.getID() + " Current value: " + ((JTextComponent) e.getComponent()).getText());
    }

    @Override
    public void focusLost(FocusEvent e) {
        logDebug("Profile " + propertyLoggingName + " Text Field focus lost." + " Cause: " + e.getCause() + " ID:" + e.getID());
        String currentText = ((JTextComponent) e.getComponent()).getText();
        if (currentValue.equals(currentText)) {
            logDebug("Current value has not changed. Not firing update with current value: " + currentValue);
        } else {
            currentValue = currentText;
            
            //The value has changed. Let's check if we have a profile we're intending to update.
            if (currentProfileOptional.isPresent()) {
                Profile currentProfile = currentProfileOptional.get();
                logInfo("Profile " + currentProfile.getName() + " " + propertyLoggingName + " text changed. New Value: " + currentText);
                if (currentText == null || currentText.isBlank()) {
                    updateFunction.accept((T) currentProfile, null);
                } else {
                    updateFunction.accept((T) currentProfile, currentText);
                }
                controller.updateProfileStatus();
            } else {
                logDebug("Profile " + propertyLoggingName + " focus lost, but no profile selected. Ignoring.");
            }
        }
    }

}
