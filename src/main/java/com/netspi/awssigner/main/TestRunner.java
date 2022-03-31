package com.netspi.awssigner.main;

import com.netspi.awssigner.controller.AWSSignerController;
import com.netspi.awssigner.log.LogLevel;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.AWSSignerConfiguration;
import com.netspi.awssigner.view.BurpTabPanel;
import java.awt.BorderLayout;
import javax.swing.*;

/*
* This has no meaningful functionality, and it only displays the UI elements
* without the elements actually working. For display purposes only.
 */
class TestRunner {

    public static void main(String[] args) {

        //Configure logging
        LogWriter.setLevel(LogLevel.DEBUG);
        //Create the view
        BurpTabPanel view = new BurpTabPanel();
        //Create the model
        AWSSignerConfiguration model = new AWSSignerConfiguration();
        //Create controller to keep them in sync
        AWSSignerController controller = new AWSSignerController(view, model);
        
        final JFrame frame = new JFrame();

        frame.setLayout(new BorderLayout());

        frame.add(view);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.pack();
    }
}
