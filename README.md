encryptedfile
================================================================================

Write OpenPGP compatible-encrypted files like it ain't no thang.
Symmetric ciphers only.

Usage
--------------------------------------------------------------------------------

Use it by itself:

    from encryptedfile import EncryptedFile
    f = EncryptedFile("hello.gpg", pass_phrase=getpass.getpass(),
                      encryption_algo=EncryptedFile.ALGO_AES256)
    f.write("super secret message")
    f.close()

Or with something passed through it:

    from encryptedfile import EncryptedFile
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


License
--------------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
<thenoviceoof@gmail> wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return
