sqlauth is a simple package for managing user authentication that is backed by 
a database. Emphatically, this package does not handle login forms or 
redirections. It only exposes a few functions for managing user passwords and 
authenticating a user's password.

### Installation

    go get github.com/BurntSushi/sqlauth


### Beta

This package is emphatically in BETA. Although most of the API is determined by 
the `gorilla/sessions` package, there are still some pieces that may need some 
changing. (For example, to allow key rotation.)

