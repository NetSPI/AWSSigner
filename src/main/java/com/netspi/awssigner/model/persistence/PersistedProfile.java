package com.netspi.awssigner.model.persistence;

import java.util.Map;
import java.util.TreeMap;

class PersistedProfile {

    String name;
    Map<String, String> keyValuePairs;

    PersistedProfile(String name, Map<String, String> keyValuePairs) {
        this.name = name;

        //ignore case for keys
        this.keyValuePairs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        this.keyValuePairs.putAll(keyValuePairs);
    }

  
}
