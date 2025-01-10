package com.netspi.awssigner.controller;

import static com.netspi.awssigner.log.LogWriter.logDebug;

import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.function.Consumer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;

/**
 * A handler class that listens to changes in a JTextComponent's text and triggers a specified callback
 * whenever the text changes. It also updates when the field loses focus, ensuring that the final edited
 * value is always captured.
 */
public class TextChangeHandler {

    private final JTextComponent textComponent;
    private final String propertyLoggingName;
    private final Consumer<String> onTextChanged;
    private String previousValue;

    /**
     * Creates a new TextChangeHandler for the specified text component.
     *
     * @param textComponent       The JTextComponent to monitor.
     * @param propertyLoggingName A descriptive name of what this text field represents (e.g. "Region", "Service").
     * @param onTextChanged       The callback to invoke whenever the text changes.
     */
    public TextChangeHandler(JTextComponent textComponent, String propertyLoggingName, Consumer<String> onTextChanged) {
        this.textComponent = textComponent;
        this.propertyLoggingName = propertyLoggingName;
        this.onTextChanged = onTextChanged;

        // Store the initial value
        this.previousValue = textComponent.getText();

        // Focus listener: When focus is lost, finalize changes if any.
        this.textComponent.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                previousValue = textComponent.getText();
                logDebug(propertyLoggingName + " Text Component focus gained. Initial value stored: " + previousValue);
            }

            @Override
            public void focusLost(FocusEvent e) {
                logDebug(propertyLoggingName + " Text Component focus lost, checking for changes.");
                handleTextChanged();
            }
        });

        // Document listener: Detect inline changes as user types
        this.textComponent.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                handleTextChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                handleTextChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                // Typically not used for plain-text components, but included for completeness.
            }
        });
    }

    /**
     * Checks if the text has changed since last recorded and, if so, triggers the onTextChanged callback.
     */
    private void handleTextChanged() {
        String currentText = textComponent.getText();
        if (!previousValue.equals(currentText)) {
            previousValue = currentText;
            logDebug(propertyLoggingName + " Text Component value changed. New value: " + currentText);
            onTextChanged.accept(currentText);
        }
    }
}
