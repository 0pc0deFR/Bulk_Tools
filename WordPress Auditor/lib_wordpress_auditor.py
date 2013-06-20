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
		print "\nAudit file: " + plugin + "\n"
		auditing(content_file)
	else:
		print "\nThe file does not exist!"
	
def load_php(plugin):
	if os.path.isfile(plugin):
		open_file = open(plugin,'r')
		reading = open_file.read()
		open_file.close()
		return reading
	else:
		return 0

def auditing(content_file):
	strings_sqli = ["$wpdb->prepare","$wpdb->get_results","$wpdb->query"]
	strings_csrf = ["wp_create_nonce", "wp_verify_nonce"]
	i = sql = csrf = 0
	while i < len(strings_sqli):
		if content_file.find(strings_sqli[i]) != -1:
			sql = 1
		i += 1

	if content_file.find("<form") != -1:
		i = 0
		csrf = 1
		while i < len(strings_csrf):
			if content_file.find(strings_csrf[i]) == 1:
				csrf = 0
			i += 1

	if sql == 1:
		print "Your plugin is potentially vulnerable to SQL Injection. For more informations: http://en.wikipedia.org/wiki/SQL_injection"
	if csrf == 1:
		print "Your plugin is potentially vulnerable to CSRF. For more informations: http://en.wikipedia.org/wiki/Cross-site_request_forgery"
	return 0
