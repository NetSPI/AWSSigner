package burp;

import javax.swing.*;

public class AWSSignerMenuItem extends JMenuItem {
    private int profileNumber;
    private String itemText;
    private boolean isEnabled;

    public AWSSignerMenuItem(String itemText, int profileNumber) {
        this.itemText = itemText;
        this.profileNumber = profileNumber;

        // This looks confusing, but "enabled" in terms of the menu item means it looks like you can
        // click on it. We want disabled items to be clickable, because they're the ones you want to change to
        isEnabled = false;
        this.setEnabled(true);
    }

    public boolean isProfileEnabled() {
        return isEnabled;
    }

    public void enableProfile() {

        // See comment in constructor to explain this weirdness
        isEnabled = true;
        this.setEnabled(false);
    }

    public void disableProfile() {

        // See comment in constructor to explain this weirdness
        isEnabled = false;
        this.setEnabled(true);
    }

    public int getProfileNumber() {
        return profileNumber;
    }

    public String toString() {
        return itemText;
    }

    @Override
    public String getText() {
        return toString();
    }
}
