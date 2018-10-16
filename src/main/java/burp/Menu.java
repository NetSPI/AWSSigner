package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;

public class Menu implements IContextMenuFactory {
    private static boolean status = false;

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<>();
        JMenuItem item;
        if (status){
            item = new JMenuItem("Disable AWS Signer");
        } else {
            item = new JMenuItem("Enable AWS Signer");
        }

        item.addMouseListener(new MouseListener() {

            public void mouseClicked(MouseEvent e) {

            }


            public void mousePressed(MouseEvent e) {

            }


            public void mouseReleased(MouseEvent e) {
                status = !status;

            }


            public void mouseEntered(MouseEvent e) {

            }


            public void mouseExited(MouseEvent e) {

            }
        });
        list.add(item);

        return list;
    }

    public static boolean getStatus(){
        return status;
    }

}
