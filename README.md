single user password/secret manager
database is just a symetrically encrypted file with serialized data.
keypit is just used to decrypt+encrypt it and access/edit it.

one change i could make:
 instead of using arrayListUnmanaged, use arrayHashMap..
 but not really necessary

 could hang keypit after a 'get' command
 and make the clipboard empty when keypit is closed?


