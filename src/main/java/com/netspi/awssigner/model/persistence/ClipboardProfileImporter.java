package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.credentials.CredentialsParser;
import com.netspi.awssigner.credentials.SigningCredentials;
import com.netspi.awssigner.log.LogWriter;
import com.netspi.awssigner.model.Profile;
import com.netspi.awssigner.model.StaticCredentialsProfile;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ClipboardProfileImporter implements ProfileImporter {

    @Override
    public List<Profile> importProfiles() {
        String clipboardText = "";
        try {
            //Gets the current clipboard text as a string
            clipboardText = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            //This shouldn't happen, but a safeguard just in case.
            if (clipboardText == null) {
                clipboardText = "";
            }
        } catch (UnsupportedFlavorException | IOException ex) {
            LogWriter.logError("Unable to obtain clipboard text. Exception: " + ex.toString());
        }

        List<Profile> profiles = new ArrayList<>(1);

        //Parse the clipboard text
        Optional<SigningCredentials> results = CredentialsParser.parseCredentialsFromText(clipboardText);
        
        //Did it work?
        if (results.isPresent()) {
            //Build a profile
            SigningCredentials creds = results.get();
            StaticCredentialsProfile profile = new StaticCredentialsProfile("clipboard");
            profile.setAccessKey(creds.getAccessKey());
            profile.setSecretKey(creds.getSecretKey());
            profile.setSessionToken(creds.getSessionToken().orElse(null));
            profiles.add(profile);
        }

        return profiles;
    }

}
