package com.netspi.awssigner.view;

import java.awt.Component;
import java.util.function.Consumer;

/**
 * This is a workaround to apply Burp styling when possible without completely destroying the MVC OOP design...
 */
public class BurpUIComponentCustomizer {

    //Default to no-op
    private static Consumer<Component> styler = ((Component c)->{});
    public static void setBurpStyler(Consumer<Component> stylingFunction){
        styler = stylingFunction;
    }
    public static void applyBurpStyling(Component component){
        styler.accept(component);
    }
}
