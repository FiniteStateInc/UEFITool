
void FfsSbomParser::extractVersionFromNode(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }
    
    // Search for Version sections in children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex child = index.child(i, 0);
        if (!child.isValid()) continue;
        
        if (model->type(child) == Types::Section && model->subtype(child) == EFI_SECTION_VERSION) {
            // Found a version section
            if (!model->hasEmptyBody(child)) {
                UString versionString = UString((const char*)model->body(child).constData());
                
                // Parse version string (format: "major.minor" or "major.minor.build")
                int lastDot = versionString.lastIndexOf('.');
                if (lastDot != -1) {
                    entry.version = versionString.left(lastDot);
                    entry.build = versionString.mid(lastDot + 1);
                } else {
                    entry.version = versionString;
                }
                
                // Add version info to description
                if (!entry.description.isEmpty()) {
                    entry.description += " (Version: " + versionString + ")";
                } else {
                    entry.description = "Version: " + versionString;
                }
                
                // Log the version we found for debugging
                logProgress("Found version for " + entry.componentName + ": " + versionString);
                return; // Use the first version section found
            }
        }
        
        // Recursively search in children
        extractVersionFromNode(child, entry);
    }
}
