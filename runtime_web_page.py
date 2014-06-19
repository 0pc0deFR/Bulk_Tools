from time import *
from urllib import *
from sys import *

if len(argv) < 2:
	print "Passer le nom de domaine en argument: http://0pc0defr.fr"
	exit(0)
debut = time()
urlopen(argv[1])
fin = time()
print "pour acceder au site", argv[1], round(fin - debut, 3), "seconde(s) de chargement"