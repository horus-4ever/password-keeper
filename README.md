# password-keeper
Application using pyqt5 to store your passwords. 

This application is multi-users. Each user must have a master password.
Users corresponding hashed passwords (sha512) are stored into the table 'users'. When a new user is created, a new table of the hashed username is created.

- master password: SHA512
- username: SHA512
- description + password: AES
  
The master password and the username are used to encrypt the fields 'description' and 'password'.
