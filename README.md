encrypt-file
================================================================================

Write OpenPGP compatible-encrypted files like it ain't no thang.
Symmetric ciphers only.

Usage
--------------------------------------------------------------------------------

Use it by itself:

    from encrypt-file import EncryptedFile
    f = EncryptedFile("hello.gpg", pass_phrase=getpass.getpass(),
                      encryption_algo=EncryptedFile.ALGO_AES256)
    f.write("super secret message")
    f.close()

Or with something passed through it:

    import PIL
    img = ... # obtain image somehow
    f = EncryptedFile("pic.png.gpg", pass_phrase=getpass.getpass(),
                      encryption_algo=EncryptedFile.ALGO_BLOWFISH)
    img.save(f, "png")


Decrypt
--------------------------------------------------------------------------------
Let's say we're using gpg:

    gpg filename

Supply the right passphrase, and tada!


FAQ
--------------------------------------------------------------------------------
 - Do you support reading?

   No, reading would mean supporting the bajillion ways that OpenPGP
   files have been created throughout history.
