=============
encryptedfile
=============

Write OpenPGP compatible-encrypted files like it ain't no thang.
Symmetric ciphers only.

-----
Usage
-----

Use it by itself::

    from encryptedfile import EncryptedFile
    f = EncryptedFile("hello.gpg", passphrase=getpass.getpass(),
                      encryption_algo=EncryptedFile.ALGO_AES256)
    f.write("super secret message")
    f.close()

Or with something passed through it::

    from encryptedfile import EncryptedFile
    import PIL
    img = ... # obtain image somehow
    f = EncryptedFile("pic.png.gpg", passphrase=getpass.getpass(),
                      encryption_algo=EncryptedFile.ALGO_BLOWFISH)
    img.save(f, "png")

Or use it in a `PEP-343 <http://www.python.org/dev/peps/pep-0343/>`_
block::

    from encryptedfile import EncryptedFile
    with EncryptedFile("txt.gpg", passphrase=getpass.getpass()) as f:
         ... use f ...

-------
Decrypt
-------

Let's say we're using gpg::

    gpg filename

Supply the right passphrase, and tada!

---
FAQ
---

-  Do you support reading?

No, reading would mean supporting the bajillion ways that OpenPGP files
have been created throughout history. That would be a pain. I may at
some point in time support reading well enough to be able to read
whatever written by this module.

-------
License
-------

"THE BEER-WARE LICENSE" (Revision 42): wrote this file. As long as you
retain this notice you can do whatever you want with this stuff. If we
meet some day, and you think this stuff is worth it, you can buy me a
beer in return
