# Radius PAP Password Decryptor

Python script which can be used to decrypt the encrypted password from captured RADIUS traffic.

The required modules for this script should already be in the new Python3 versions, but in any case the required modules are:
- hashlib (md5)
- binascii

The details on how the RADIUS password encryption works can be found in An Analysis of the RADIUS Authentication Protocol by Joshua Hill specifically chapter 2.1., currently at the link https://www.untruth.org/~josh/security/radius/radius-auth.html. Alo check out the RADIUS RFC at https://www.rfc-editor.org/rfc/rfc2865.

# HOW DOES IT WORK

1. Download the script and install the modules
2. Start the script
3. Ask for help
4. Fill out the input
5. Wait for the code to perform the brute force

NOTE

Check out the pictures that reference where information in the captured traffic can be found.

# TODO

- code currently works only if the user password is less than 16 charaters


# DISCLAIMER

The information and code in this repository is for educational puproses regarding the topic of ethical hacking, penetration testing and similar fields of computer scinece. I will not assume responsibility for the malicious use or damage done if this information and/or code is to be used in an unethical way.
