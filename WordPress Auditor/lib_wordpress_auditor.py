#!/usr/bin/python
import sys
import os.path

def main():
	if len(sys.argv) < 2:
		print "Example: "
		print sys.argv[0] + " file.php"
		sys.exit()
	plugin = sys.argv[1]
	content_file = load_php(plugin)
	if content_file:
		print "Audit file: " + plugin
		auditing(content_file)
	else:
		print "The file does not exist"
	
def load_php(plugin):
	if os.path.isfile(plugin):
		open_file = open(plugin,'r')
		reading = open_file.read()
		open_file.close()
		return reading
	else:
		return 0

def auditing(content_file):
	strings = ["$wpdb->prepare","$wpdb->get_results","$wpdb->query","move_uploaded_file"]
	i = 0
	while i < len(strings):
		if content_file.find(strings[i]) != -1:
			print strings[i] + " founded"
		i += 1

		
	return 0