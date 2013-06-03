#Decode FTP, login et mot de passe dans les serveurs 1337 Stealer

import sys
import binascii
import lib_decode

fichier = sys.argv[1]

file = open(fichier,'rb')
lecture = file.read()
file.close()

if lecture.find("*[H-E-R-E]*") > 1:
	locate = lecture.find("*[H-E-R-E]*")
	locate = lecture[locate+13:len(lecture)]
elif lecture.find("FTP~") > 1:
	locate = lecture.find("FTP~")
	locate = lecture[locate+4:len(lecture)]
	ftp_hex = locate[0:locate.find("~")]
	login_hex = locate[locate.find("~")+1:len(locate)]
	login_hex = login_hex[0:login_hex.find("~")]
	pass_hex = locate[locate.find("~")+len(login_hex)+2:locate.find("~1")]
	ftp = lib_decode.decode_hexa_ascii(ftp_hex)
	login = lib_decode.decode_hexa_ascii(login_hex)
	password = lib_decode.decode_hexa_ascii(pass_hex)
	print "FTP: "+ftp
	print "Login: "+login
	print "Password: "+password
