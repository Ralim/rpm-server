# RPM-Serve

This is a dumb project that only exists because I couldn't find it elsewhere.

Given a folder of RPM packages, this serves over http a repository for dnf to install these packages. Including the http index pages for manual browsing.

This exists purely because some vendors (aws) refuse to provide respositories and instead want us to manually load their trust-me-bro rpm files.

The usecase is that this runs in a container, you mount in your RPM folder as read-only.
You also provide a gpg key, and the server signs the packages with it on the fly (if you want).
