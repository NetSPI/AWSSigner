package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class Menu implements IContextMenuFactory {
    private static JMenu subMenu;
    private static AWSSignerMenuItem enabledMenuItem;
    private static AWSSignerMenuItem[] menuItems = new AWSSignerMenuItem[] {};

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<>();

        // Create menu items
        subMenu = new JMenu("AWSSigner");

        // Always create the disable signer item
        JMenuItem disableItem = new JMenuItem("Disable AWSSigner");
        initializeDisableItem(disableItem);
        if (enabledMenuItem == null) {
            disableItem.setEnabled(false);
        } else {
            disableItem.setEnabled(true);
        }

        subMenu.add(disableItem);

        // Add a menu item for every profile we currently have
        for (AWSSignerMenuItem menuItem : menuItems) {
            initializeMenuItem(menuItem);
            subMenu.add(menuItem);
        }

        list.add(subMenu);
        return list;
    }

    public static void setMenuItems(AWSSignerMenuItem[] menuItems) {
        Menu.menuItems = menuItems;
    }

    private void initializeMenuItem(AWSSignerMenuItem newMenuItem) {
        newMenuItem.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

                // Enable the profile, and disable the old profile
                if (enabledMenuItem != null) {
                    enabledMenuItem.disableProfile();
                }
                newMenuItem.enableProfile();
                enabledMenuItem = newMenuItem;
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        if (newMenuItem.isProfileEnabled()) {
            if (enabledMenuItem != null) {
                enabledMenuItem.disableProfile();
            }
            newMenuItem.enableProfile();
            enabledMenuItem = newMenuItem;
        }
    }

    private static void initializeDisableItem(JMenuItem menuItem) {
        menuItem.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

                // To disable the signer, set the enabled item to null
                if (enabledMenuItem != null) {
                    enabledMenuItem.disableProfile();
                    enabledMenuItem = null;
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
    }

    public static int getEnabledProfile(){
        if (enabledMenuItem == null) {
            return 0;
        }
        return enabledMenuItem.getProfileNumber();
    }

    // I expect most of the time, the profile will be enabled through the context menu, but
    // we support enabling profiles through the signer tab too, which is why this needs to be here
    public static void setEnabledProfile(int profile) {
        if (enabledMenuItem != null) {
            enabledMenuItem.disableProfile();
        }

        // Also allow the signer tab to disable the signer
        if (profile == 0) {
            enabledMenuItem.disableProfile();
            enabledMenuItem = null;
        } else {

            // I don't want to keep a map of all the profiles. Just iterate through them until we find the right one
            for (AWSSignerMenuItem menuItem : menuItems) {
                if (menuItem.getProfileNumber() == profile) {
                    menuItem.enableProfile();
                    enabledMenuItem = menuItem;
                }
            }
        }
    }

}
