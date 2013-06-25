#!/usr/bin/python
import sys
import os.path

def main():
	if len(sys.argv) < 2:
		print "Example: "
		print sys.argv[0] + " file.php"
		print sys.argv[0] + " pluginDir"
		sys.exit()
	plugin = sys.argv[1]
	load_plugin(plugin)
		

def load_plugin(plugin):
	if os.path.isfile(plugin):
		print "\nAudit file: " + plugin + "\n"
		read = load_php(plugin)
		auditing(read)
	elif os.path.isdir(plugin):
		for f in os.listdir(plugin):
			if plugin[len(plugin)-1:] != "/":
				plugin = plugin + "/"
			load_plugin(plugin + f)
	else:
		print "\nThe file does not exist!"
	

def load_php(plugin):
	if os.path.isfile(plugin):
		open_file = open(plugin,'r')
		reading = open_file.read()
		open_file.close()
		return reading

def csrf(content_file):
	strings_csrf = ["wp_create_nonce", "wp_verify_nonce"]
	start = end = i = 0
	csrf = None
	while True:
		start = content_file.find("<form", end)
		end = content_file.find("</form>", start)
		if start != -1 and end != -1:
			csrf = 1
			while i < len(strings_csrf):
				if content_file.find(strings_csrf[i], start, end) != -1:
					csrf = 0
				i += 1
		else:
			break

	if csrf == 1:
		print "Your plugin is potentially vulnerable to CSRF. For more informations: http://en.wikipedia.org/wiki/Cross-site_request_forgery"

def sqli(content_file):
	strings_sqli = ["$wpdb->get_results","$wpdb->query"]
	i = sqli = 0
	while i < len(strings_sqli):
		if content_file.find(strings_sqli[i]) != -1 and content_file.find("$wpdb->prepare") == -1:
			sqli = 1
		i += 1
	if sqli == 1:
		print "Your plugin is potentially vulnerable to SQL Injection. For more informations: http://en.wikipedia.org/wiki/SQL_injection"

def auditing(content_file):
	csrf(content_file)
	sqli(content_file)
	return 0
