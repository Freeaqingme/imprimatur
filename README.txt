If you do not have a GPG key yet:
  gpg --full-gen-key

Print your keyring:
  gpg --list-keys  --with-keygrip

Pick the keygrip of the key you want to sign with (must have flag S).

Next up, sign the file:
  imprimatur sign ./original.pdf --keygrip <keygrip>
