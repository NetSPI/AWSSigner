package com.netspi.awssigner.controller;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.*;
import java.util.regex.*;
import static com.netspi.awssigner.log.LogWriter.logError;

/**
 * Handles regex-based search, highlighting, and replacement for a JTextArea.
 */
public class RegexHandler {

    private final JTextArea textArea;
    private final Highlighter highlighter;
    private final java.util.List<int[]> matchPositions;
    private int currentMatchIndex = -1;
    private String currentRegex; // Store the last used regex pattern

    public RegexHandler(JTextArea textArea) {
        this.textArea = textArea;
        this.highlighter = textArea.getHighlighter();
        this.matchPositions = new ArrayList<>();
        this.currentRegex = null;
    }

    public void findAndHighlightNext(String regex) throws PatternSyntaxException {
        if (currentRegex == null || !currentRegex.equals(regex)) {
            // Perform a new search if the regex changes
            findAllMatches(regex);
            currentMatchIndex = 0; // Start with the first match
        } else if (!matchPositions.isEmpty()) {
            // Cycle to the next match if there are matches
            currentMatchIndex = (currentMatchIndex + 1) % matchPositions.size();
        }

        if (!matchPositions.isEmpty()) {
            updateHighlights(); // Highlight matches and the current match
        }
    }

    /**
     * Finds all matches and stores their positions.
     *
     * @param regex The regex pattern to search for
     * @throws PatternSyntaxException if the regex is invalid
     */
    private void findAllMatches(String regex) throws PatternSyntaxException {
        clearHighlights();
        matchPositions.clear();

        currentRegex = regex; // Store the current regex
        String content = textArea.getText();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            matchPositions.add(new int[]{start, end});
        }

        currentMatchIndex = matchPositions.isEmpty() ? -1 : 0; // Reset match index
    }

    /**
     * Replaces the current highlighted match with the given replacement.
     *
     * @param replacement The text to replace the current match
     */
    public void replaceCurrentMatch(String replacement) {
        if (!hasCurrentMatch()) {
            logError("No current match to replace.");
            return;
        }

        try {
            String content = textArea.getText();
            int[] currentMatch = matchPositions.get(currentMatchIndex);
            int start = currentMatch[0];
            int end = currentMatch[1];

            // Replace the current match using a quoted replacement
            String updatedContent = content.substring(0, start)
                    + Matcher.quoteReplacement(replacement)
                    + content.substring(end);
            textArea.setText(updatedContent);

            // Adjust subsequent match positions
            int adjustment = replacement.length() - (end - start);
            matchPositions.remove(currentMatchIndex);

            for (int i = currentMatchIndex; i < matchPositions.size(); i++) {
                matchPositions.get(i)[0] += adjustment;
                matchPositions.get(i)[1] += adjustment;
            }

            // Highlight remaining matches
            highlightAllMatches();

            // Highlight the next match if any
            if (!matchPositions.isEmpty()) {
                currentMatchIndex = currentMatchIndex % matchPositions.size();
                highlightCurrentMatch();
            } else {
                currentMatchIndex = -1; // Reset if no matches remain
            }
        } catch (Exception e) {
            logError("Error replacing current match: " + e.getMessage());
        }
    }

    /**
     * Highlights all matches in yellow, except the current match.
     */
    private void highlightAllMatches() {
        clearHighlights(); // Clear existing highlights
        try {
            for (int i = 0; i < matchPositions.size(); i++) {
                if (i != currentMatchIndex) { // Skip the current match
                    int[] match = matchPositions.get(i);
                    highlighter.addHighlight(match[0], match[1], new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW));
                }
            }
        } catch (BadLocationException e) {
            logError("Error highlighting matches: " + e.getMessage());
        }
    }

    /**
     * Highlights the current match in orange.
     */
    private void highlightCurrentMatch() {
        if (!hasCurrentMatch()) {
            return;
        }

        try {
            int[] currentMatch = matchPositions.get(currentMatchIndex);
            highlighter.addHighlight(currentMatch[0], currentMatch[1], new DefaultHighlighter.DefaultHighlightPainter(Color.ORANGE));
            textArea.setCaretPosition(currentMatch[0]); // Move caret to the current match
        } catch (BadLocationException e) {
            logError("Error highlighting current match: " + e.getMessage());
        }
    }

    /**
     * Highlights all matches and the current match.
     */
    private void updateHighlights() {
        highlightAllMatches(); // Highlight all matches in yellow, except the current one
        highlightCurrentMatch(); // Highlight the current match in orange
    }

    /**
     * Replaces all matches with the given replacement.
     *
     * @param replacement The text to replace all matches
     */
    public void replaceAllMatches(String replacement) {
        if (matchPositions.isEmpty() || currentRegex == null) {
            logError("No matches to replace.");
            return;
        }

        try {
            String content = textArea.getText();
            // Use quoted replacement for safety
            String updatedContent = content.replaceAll(currentRegex, Matcher.quoteReplacement(replacement));
            textArea.setText(updatedContent);

            clearHighlights();
            matchPositions.clear();
        } catch (Exception e) {
            logError("Error replacing all matches: " + e.getMessage());
        }
    }

    /**
     * Clears all highlights in the text area.
     */
    private void clearHighlights() {
        try {
            highlighter.removeAllHighlights();
        } catch (Exception e) {
            logError("Error clearing highlights: " + e.getMessage());
        }
    }

    /**
     * Checks if a current match is highlighted.
     *
     * @return True if a current match exists, otherwise false
     */
    public boolean hasCurrentMatch() {
        return currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size();
    }

    /**
     * Gets the total number of matches found.
     *
     * @return The count of matches
     */
    public int getMatchCount() {
        return matchPositions.size();
    }
}