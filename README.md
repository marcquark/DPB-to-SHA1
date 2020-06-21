# DPB-to-SHA1
A small tool to deal with the Encrypted Data Structure found in the Office VBA File Format. It can decrypt the raw data and recover the SHA-1 hash and salt (Microsoft calls it "Key") from a protected VBA Macro. While it's typically not necessary to crack the password in order to access the VBA code, this tool is handy if the password itself is what you're after

## How to build
Simply use gcc to compile it
```
g++ -o dpb-to-sha1 main.cpp
```

## How to run
The program expects the DPB value from vbaProject.bin as a parameter. It can be easily accessed by unzipping the MS Office document. Then call the program like so
```
./dpb-to-sha1 FCFE5054B04FCD4FCDB03350CD27DCB79AACA3F42F5179FFF4B1A293D0B04861AA321BF5767C
```
The example has been created using a password of "12345" and produces the following output
```
FCFE5054B04FCD4FCDB03350CD27DCB79AACA3F42F5179FFF4B1A293D0B04861AA321BF5767C
ffffffff68e9a7197cb595175af0bec373c5e5575a62731140f1d68700
68e9a719
7cb595175af0bec373c5e5575a62731140f1d687
```
The lines have the following meaning
1. Simply repeats the input
2. The decrypted data structure in hex
3. The recovered salt in hex. The Microsoft specification refers to it as "Key"
4. The recovered SHA-1 hash in hex

## How to crack
Cracking the hash is easy, but ultimately the password strength determines whether you're going to be successful. Here's how hashcat can be used to recover the password "12345" from the example:
```
.\hashcat.exe -m 110 -O -a 3 --hex-salt 7cb595175af0bec373c5e5575a62731140f1d687:68e9a719 ?d?d?d?d?d
```
* `-m 110` specifies the hash type (salted SHA-1)
* `-O` tells hashcat to use optimized kernels
* `-a 3` specifies the attack mode (brute-force)
* `--hex-salt` tells hashcat that the salt is given in hex
* `?d?d?d?d?d` is the password mask (5 digits)

The corresponding output looks like this
```
7cb595175af0bec373c5e5575a62731140f1d687:68e9a719:12345
```

## Relevant documentation
* Encrypted Data Structure https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/a2ad3aa7-e180-4ccb-8511-7e0eb49a0ad9
* Decryption Routine https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/7e9d84fe-86e3-46d6-aaff-8388e72c0168
* Password Hash Data Structure https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/9d9f81e6-f92e-4338-a242-d38c1fcceed6
* Decode Nulls in the Password Hash Data Structure https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/5797c2e1-4c86-4f44-89b4-1edb30da00cc
