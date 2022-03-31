package com.netspi.awssigner.model.persistence;

import com.netspi.awssigner.model.Profile;
import java.util.List;

public interface ProfileImporter {
    public List<Profile> importProfiles();
}
