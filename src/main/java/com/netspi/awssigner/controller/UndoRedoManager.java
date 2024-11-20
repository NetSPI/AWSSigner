package com.netspi.awssigner.controller;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;
import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.ActionEvent;

public class UndoRedoManager {

    public static void addUndoRedoFunctionality(JTextComponent textComponent) {
        final UndoManager undoManager = new UndoManager();

        // Add UndoableEditListener to the document
        textComponent.getDocument().addUndoableEditListener(e -> undoManager.addEdit(e.getEdit()));

        // Get the platform-specific menu shortcut key mask
        int menuShortcutKeyMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

        // Undo key stroke
        KeyStroke undoKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuShortcutKeyMask);

        // Redo key strokes
        KeyStroke redoKeyStroke1 = KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuShortcutKeyMask | InputEvent.SHIFT_DOWN_MASK);
        KeyStroke redoKeyStroke2 = KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuShortcutKeyMask | InputEvent.SHIFT_DOWN_MASK);

        // Bind the undo action
        textComponent.getInputMap().put(undoKeyStroke, "Undo");
        textComponent.getActionMap().put("Undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (undoManager.canUndo()) {
                    undoManager.undo();
                }
            }
        });

        // Bind the redo actions
        textComponent.getInputMap().put(redoKeyStroke1, "Redo");
        textComponent.getInputMap().put(redoKeyStroke2, "Redo");
        textComponent.getActionMap().put("Redo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (undoManager.canRedo()) {
                    undoManager.redo();
                }
            }
        });
    }
}
