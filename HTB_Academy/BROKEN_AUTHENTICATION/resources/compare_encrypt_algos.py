import scrypt
import bcrypt
import datetime
import hashlib

rounds = 100
salt = bcrypt.gensalt()

t0 = datetime.datetime.now()

for x in range(rounds):
    scrypt.hash(str(x).encode(), salt)

t1 = datetime.datetime.now()

for x in range(rounds):
    hashlib.sha1(str(x).encode())

t2 = datetime.datetime.now()

for x in range(rounds):
    bcrypt.hashpw(str(x).encode(), salt)

t3 = datetime.datetime.now()

print("sha1:   {}\nscrypt: {}\nbcrypt: {}".format(t2-t1,t1-t0,t3-t2))