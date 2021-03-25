# Encrypter - Decrypter #
### 24/03/21 ###
#### Encrypter ####
Given a 'file.txt' as input, it encrypts its content and write it into "file.txt.enc".

#### Decrypter ####
It takes the newly encrypted file, "file.txt.enc", decrypt it and stores the plaintext in "file.txt.enc.dec".

The 'school' version allows you to encrypt only small files, in this version you can use a file of any size.

The approach used to write the code followed the guidelines of defensive programming.
The program is memory safe, no memory leaks are possible.

#### How to run ####
Just type "make" and then "make test".
If you want to test the memory security, type "make valgrind_test".