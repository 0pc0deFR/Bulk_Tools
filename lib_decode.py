import binascii

def decode_hexa_ascii(data):
	data = data.replace("%","")
	data = data.replace(":","")
	data = data.replace("x","")
	data = binascii.a2b_hex(data)
	return data