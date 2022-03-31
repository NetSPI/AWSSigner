package com.netspi.awssigner.controller;

import static com.netspi.awssigner.log.LogWriter.*;
import com.netspi.awssigner.model.AWSSignerConfiguration;
import com.netspi.awssigner.model.Profile;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.function.Consumer;


class ComboBoxProfileSelectionListener implements ItemListener {

    private final AWSSignerConfiguration model;
    private final String comboboxFriendlyName;
    private final Consumer<Profile> profileAssignmentFunction;

    public ComboBoxProfileSelectionListener(AWSSignerConfiguration model, String comboboxFriendlyName, Consumer<Profile> profileAssignmentFunction) {
        this.model = model;
        this.comboboxFriendlyName = comboboxFriendlyName;
        this.profileAssignmentFunction = profileAssignmentFunction;
    }

    @Override
    public void itemStateChanged(ItemEvent event) {
        logDebug("\"" + comboboxFriendlyName + "\" Profile ComboBox Item Event:" + " StateChange: " + event.getStateChange() + " Item: " + event.getItem());
        if (event.getStateChange() == ItemEvent.SELECTED) {
            String selectedProfileName = (String) event.getItem();
            if (selectedProfileName.trim().isEmpty()) {
                logInfo("\"" + comboboxFriendlyName + "\" Profile unset");
                profileAssignmentFunction.accept(null);
            } else {
                logInfo("New \"" + comboboxFriendlyName + "\" Profile set: " + selectedProfileName);
                profileAssignmentFunction.accept(model.getProfileForName(selectedProfileName).orElse(null));
            }
        }
    }

}
