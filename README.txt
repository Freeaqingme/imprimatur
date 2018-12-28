If you do not have a GPG key yet:
  gpg --full-gen-key

Print your keyring:
  gpg --list-keys  --with-keygrip

Pick the keygrip of the key you want to sign with (must have flag S).

Next up, sign the file:
  imprimatur sign ./original.pdf --keygrip <keygrip>

Then, either verify the keys, or render it including signatures:
  imprimatur display ./original.signed.pdf
  imprimatur verify ./original.signed.pdf
