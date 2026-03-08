apass

A small terminal password vault written in Go.

This repository contains:
- apass.go        - source code
- apass           - compiled binary (name may vary by platform)

What it does
- Stores account entries in an encrypted local vault
- Uses a master password to protect the private key
- Encrypts the vault with age
- Supports contacts and encrypted message sharing
- Runs as an interactive terminal app

Main features
- Create and unlock a local vault
- Add, edit, list, view, and delete password entries
- Add and remove contacts by public key
- Encrypt short messages to saved contacts
- Export vault contents as plaintext JSON with confirmation

Files created at runtime
The program creates a local directory:

.apass/

Inside it:
- key.age    - encrypted private key
- vault.age  - encrypted vault data

Basic usage
Run the program from a terminal:

./apass

On first run:
- enable execute permissions: $ chmod +x apass
- It creates a new vault
- It asks you to set a master password

On later runs:
- It asks for your master password
- It unlocks the existing vault

Commands
ls
- List saved entries and contacts

cat ACCOUNT
- Show the username and password for an account

sort AZ
sort ZA
sort Date
- Sort entries by account name or edited timestamp

add
- Add a new vault entry

add contact NAME
- Add or update a contact public key

edit ACCOUNT
- Edit an existing account

del ACCOUNT
- Delete an account

del contact NAME
- Delete a contact

send NAME
- Encrypt a message to a saved contact and print armored output

pubkey
- Print your public key

lock
- Clear the screen and require unlock again

export [file]
- Export the vault as plaintext JSON
- Prompts before exporting
- Prompts before overwriting an existing file
- Defaults to a file in your home directory if no path is given

help
- Show command summary

exit
quit
- Leave the program

Security notes
- Vault data is encrypted at rest
- Password input is hidden in the terminal
- The export command writes plaintext JSON, so use it carefully
- Anyone with your unlocked terminal session can read displayed secrets
- Keep file permissions restricted and avoid committing real vault data

Building
You need Go and the required dependencies.

Typical build command:

go build -o apass apass.go

If you are building on Windows:

go build -o apass.exe apass.go

Running
Linux/macOS:
./apass

Windows:
apass.exe

Important
- Do not commit your real .apass directory
- Do not commit plaintext exports
- Do not share your master password or private key
- Treat exported JSON as sensitive data
