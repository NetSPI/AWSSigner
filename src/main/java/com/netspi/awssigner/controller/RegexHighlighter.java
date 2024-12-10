package com.netspi.awssigner.controller;

import static com.netspi.awssigner.log.LogWriter.logError;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * RegexHighlighter provides search, highlight, and replace capabilities for text in a JTextArea
 * using regex patterns. Matches are highlighted to help the user visually locate and manipulate
 * specific segments of text.
 *
 * Usage:
 * 1. Instantiate with a JTextArea.
 * 2. Call findAndHighlightNext(regex) to initiate searching.
 * 3. Use replaceCurrentMatch or replaceAllMatches as needed.
 */
public class RegexHighlighter {

    private final JTextArea textArea;
    private final Highlighter highlighter;
    private final List<int[]> matchPositions;
    private int currentMatchIndex = -1;
    private String currentRegex;

    /**
     * Creates a new RegexHighlighter for a given JTextArea.
     *
     * @param textArea The JTextArea to search and highlight.
     */
    public RegexHighlighter(JTextArea textArea) {
        this.textArea = textArea;
        this.highlighter = textArea.getHighlighter();
        this.matchPositions = new ArrayList<>();
        this.currentRegex = null;
    }

    /**
     * Finds matches for the given regex and highlights them. If called repeatedly with the same regex,
     * it cycles through found matches. If a new regex is provided, it clears previous highlights
     * and searches anew.
     *
     * @param regex The regex pattern to find.
     * @throws PatternSyntaxException If the provided regex is invalid.
     */
    public void findAndHighlightNext(String regex) throws PatternSyntaxException {
        if (currentRegex == null || !currentRegex.equals(regex)) {
            // Perform a new search if the regex changes
            findAllMatches(regex);
            currentMatchIndex = 0; // Start at the first match
        } else if (!matchPositions.isEmpty()) {
            // Cycle to the next match if there are matches
            currentMatchIndex = (currentMatchIndex + 1) % matchPositions.size();
        }

        if (!matchPositions.isEmpty()) {
            updateHighlights();
        }
    }

    /**
     * Finds all matches of the given regex in the text and stores their positions.
     *
     * @param regex The regex pattern to search for.
     * @throws PatternSyntaxException if the regex is invalid
     */
    private void findAllMatches(String regex) throws PatternSyntaxException {
        clearHighlights();
        matchPositions.clear();

        currentRegex = regex;
        String content = textArea.getText();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            matchPositions.add(new int[]{start, end});
        }

        currentMatchIndex = matchPositions.isEmpty() ? -1 : 0;
    }

    /**
     * Replaces the current highlighted match with the given replacement text.
     *
     * @param replacement The replacement text.
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

            // Perform the replacement
            String updatedContent = content.substring(0, start)
                    + Matcher.quoteReplacement(replacement)
                    + content.substring(end);
            textArea.setText(updatedContent);

            // Adjust subsequent matches due to the changed length
            int adjustment = replacement.length() - (end - start);
            matchPositions.remove(currentMatchIndex);

            for (int i = currentMatchIndex; i < matchPositions.size(); i++) {
                matchPositions.get(i)[0] += adjustment;
                matchPositions.get(i)[1] += adjustment;
            }

            highlightAllMatches();

            if (!matchPositions.isEmpty()) {
                currentMatchIndex = currentMatchIndex % matchPositions.size();
                highlightCurrentMatch();
            } else {
                currentMatchIndex = -1;
            }
        } catch (Exception e) {
            logError("Error replacing current match: " + e.getMessage());
        }
    }

    /**
     * Replaces all matches of the current regex in the text with the given replacement text.
     *
     * @param replacement The replacement text.
     */
    public void replaceAllMatches(String replacement) {
        if (matchPositions.isEmpty() || currentRegex == null) {
            logError("No matches to replace.");
            return;
        }

        try {
            String content = textArea.getText();
            String updatedContent = content.replaceAll(currentRegex, Matcher.quoteReplacement(replacement));
            textArea.setText(updatedContent);

            clearHighlights();
            matchPositions.clear();
        } catch (Exception e) {
            logError("Error replacing all matches: " + e.getMessage());
        }
    }

    /**
     * Highlights all matches in yellow. The current match (if any) is highlighted in orange.
     */
    private void highlightAllMatches() {
        clearHighlights(); // Clear existing highlights
        try {
            for (int i = 0; i < matchPositions.size(); i++) {
                if (i != currentMatchIndex) {
                    int[] match = matchPositions.get(i);
                    highlighter.addHighlight(match[0], match[1], new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW));
                }
            }
        } catch (BadLocationException e) {
            logError("Error highlighting matches: " + e.getMessage());
        }
    }

    /**
     * Highlights the current match in orange to distinguish it from other matches.
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
     * Updates the highlights to reflect the current set of matches and which one is "current".
     */
    private void updateHighlights() {
        highlightAllMatches();
        highlightCurrentMatch();
    }

    /**
     * Clears all highlights from the text area.
     */
    private void clearHighlights() {
        try {
            highlighter.removeAllHighlights();
        } catch (Exception e) {
            logError("Error clearing highlights: " + e.getMessage());
        }
    }

    /**
     * Checks if there is a current match selected.
     *
     * @return True if there is a current match, false otherwise.
     */
    public boolean hasCurrentMatch() {
        return currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size();
    }

    /**
     * Returns the count of all found matches.
     *
     * @return The number of matches found for the current regex.
     */
    public int getMatchCount() {
        return matchPositions.size();
    }
}
