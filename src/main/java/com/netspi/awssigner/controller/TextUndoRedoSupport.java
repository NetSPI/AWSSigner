package com.netspi.awssigner.controller;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/**
 * TextUndoRedoSupport installs undo/redo functionality on a JTextComponent.
 * It uses a Swing UndoManager to track edits and binds platform-standard keyboard shortcuts:
 * - Ctrl+Z (or Cmd+Z on macOS) for undo
 * - Ctrl+Shift+Z (or Cmd+Shift+Z on macOS) for redo
 *
 * This ensures that the user can use familiar shortcuts to undo and redo text changes.
 */
public class TextUndoRedoSupport {

    private final JTextComponent textComponent;
    private final UndoManager undoManager;

    /**
     * Creates a new TextUndoRedoSupport and attaches undo/redo functionality to the provided text component.
     *
     * @param textComponent The JTextComponent to enhance with undo/redo support.
     */
    public TextUndoRedoSupport(JTextComponent textComponent) {
        this.textComponent = textComponent;
        this.undoManager = new UndoManager();

        // Listen to document changes and add them to the UndoManager
        textComponent.getDocument().addUndoableEditListener(e -> undoManager.addEdit(e.getEdit()));

        // Determine platform-specific shortcut key mask
        int menuShortcutKeyMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

        // Undo key stroke: Ctrl/Cmd+Z
        KeyStroke undoKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuShortcutKeyMask);

        // Bind Undo action
        textComponent.getInputMap().put(undoKeyStroke, "Undo");
        textComponent.getActionMap().put("Undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (undoManager.canUndo()) {
                    undoManager.undo();
                }
            }
        });

        // Redo key strokes
        KeyStroke redoKeyStroke1 = KeyStroke.getKeyStroke(KeyEvent.VK_Y, menuShortcutKeyMask);
        KeyStroke redoKeyStroke2 = KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuShortcutKeyMask | InputEvent.SHIFT_DOWN_MASK);

        // Bind both keystrokes to the same "Redo" action
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
