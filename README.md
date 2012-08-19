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
