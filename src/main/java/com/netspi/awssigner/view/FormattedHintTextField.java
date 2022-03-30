package com.netspi.awssigner.view;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.InputVerifier;
import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.border.Border;

/**
 * Hacky workaround to enable a hint message in a format-validated text field.
 *
 * Cobbled together from here:
 * https://stackoverflow.com/questions/1738966/java-jtextfield-with-input-hint
 * https://itqna.net/questions/17762/how-validate-text-field-inputverifier
 */
public class FormattedHintTextField extends JTextField {

    private final boolean required;
    private Pattern format = null;
    private final String additionalHelpText;

    public FormattedHintTextField(boolean required) {
        //Pass along required and allow any non-empty input for the pattern
        this(required, Pattern.compile(".+"));
    }

    public FormattedHintTextField(boolean required, Pattern format) {
        //Pass along required and format, no additional help text
        this(required, format, null);
    }

    public FormattedHintTextField(boolean required, Pattern format, String additionalHelpText) {
        super();
        this.required = required;
        this.format = format;
        this.additionalHelpText = additionalHelpText;

        setInputVerifier(new InputVerifier() {
            Border originalBorder;

            @Override
            public boolean verify(JComponent input) {

                JTextField comp = (JTextField) input;
                String inputText = comp.getText();

                //Check for null/empty input
                if (inputText == null || inputText.isBlank()) {
                    //Return indication based on whether or not the input is required
                    return !required; 
                } else {
                    //There is some input. Check it against the expected format
                    return format.matcher(inputText).matches();
                }
            }

            @Override
            public boolean shouldYieldFocus(JComponent input) {
                boolean isValid = verify(input);

                if (!isValid) {
                    originalBorder = originalBorder == null ? input.getBorder() : originalBorder;
                    input.setBorder(BorderFactory.createLineBorder(Color.red, 2));
                } else {
                    if (originalBorder != null) {
                        input.setBorder(originalBorder);
                        originalBorder = null;
                    }
                }

                //If we return isValid here, we can keep focus when invalid input is submitted. This feels wrong though.
                return true;
            }
        });
    }

    @Override
    public void paintComponent(final Graphics USE_g2d_INSTEAD) {
        //Check optional or required
        String hint = required ? "Required" : "Optional";
        //Add help text, if we have any
        if (additionalHelpText != null && !additionalHelpText.trim().isEmpty()) {
            hint = hint + " - " + additionalHelpText;
        }

        if (!this.isEnabled() || !this.isEditable()) {
            hint = "Input Disabled";
        }

        final Graphics2D g2d = (Graphics2D) USE_g2d_INSTEAD;
        super.paintComponent(g2d);

        if (getText().isEmpty()) {
            g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            final Insets ins = getInsets();
            final FontMetrics fm = g2d.getFontMetrics();

            final int cB = getBackground().getRGB();
            final int cF = getForeground().getRGB();
            final int m = 0xfefefefe;
            final int c2 = ((cB & m) >>> 1) + ((cF & m) >>> 1);

            //Only update the color if it's enabled or editabled. Otherwise leave default
            if (this.isEnabled() || this.isEditable()) {
                g2d.setColor(new Color(c2, true));
            }

            g2d.setFont(g2d.getFont().deriveFont(Font.ITALIC));
            g2d.drawString(hint, ins.left, getHeight() - fm.getDescent() - ins.bottom);
        }
    }

    public boolean isRequired() {
        return required;
    }

    public Pattern getFormat() {
        return format;
    }

}
