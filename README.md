# password
Using your favorite language( I use python), implement a little app that has the following features:
•Given a (Username, Password) pair in ASCII; store the pair to a file
$ python sourcecode.py -a -u <username> -p <password>
# password will be saved in "password_manager.db" with sqlite3 
•Given a (Username, Password) pair in ASCII; check if the username exists and if the password matches the one stored in a file. If it does, don't store the duplicate.
$ python sourcecode.py -c -u username -p password 
•Using a flag the user should be able to choose ECB, CTR or CBC modes.
Default it will be encrypted in ECB mode, use -e to switch encryption methods among ECB, CTR and CBC 
$ python sourcecode.py -a -u <username> -p <password> -e ECB 
$ python sourcecode.py -a -u <username> -p <password> -e CTR
$ python sourcecode.py -a -u <username> -p <password> -e CBC
