#!/usr/bin/python
import sys
import os
import zipfile
import hashlib
import shutil

# Configuration
tmp_dir = "/tmp/" #Example: /tmp/
ignored_extension = ['.jpg', '.png', '.gif'] #You can add your ignored extensions. Files with these extensions will not be audited.
xss_detection_beta = True #The XSS detection is in beta and it is possible to have many false positives. You can disable XSS detection with False parameter
# End Configuration

#Don't modification
uri = None

def main():
	if len(sys.argv) < 2:
		print "Example: "
		print sys.argv[0] + " file.php"
		print sys.argv[0] + " pluginDir"
		print sys.argv[0] + " archive.zip"
		sys.exit()
	plugin = sys.argv[1]
	if zipfile.is_zipfile(plugin):
		load_archive(plugin)
	else:
		load_plugin(plugin)
	if uri:
		print "\n" + uri

def load_archive(plugin):
	archive_zip = zipfile.ZipFile(plugin)
	archive_info = zipfile.ZipInfo(plugin)
	hash_dir = hashlib.md5(str(archive_info)).hexdigest()
	
	archive_zip.extractall(tmp_dir + hash_dir)
	print "\nThe archive as been unpacked in: " + tmp_dir + hash_dir
	load_plugin(tmp_dir + hash_dir)
	shutil.rmtree(tmp_dir + hash_dir)
	print "\nThe temporary directory has been removed"

def load_plugin(plugin):
	if os.path.isfile(plugin):
		i = 0
		extension = os.path.splitext(plugin)
		global ignored_extension
		if not extension[1] in ignored_extension:
			print "\nAudit file: " + plugin
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
			i = 0
		else:
			break

	if csrf == 1:
		print "Your plugin is potentially vulnerable to CSRF. For more informations: http://en.wikipedia.org/wiki/Cross-site_request_forgery"
		
def xss(content_file):
	strings_xss = ["esc_html", "esc_js", "esc_textarea"]
	start = end = i = 0
	xss = None
	while True:
		start = content_file.find("echo", end)
		end = content_file.find(";", start)
		if start != -1 and end != -1 and content_file.find("$", start, end) != -1:
			xss = 1
			while i < len(strings_xss):
				if content_file.find(strings_xss[i], start, end) != -1:
					xss = 0
				i += 1
			i = 0
		else:
			break

	if xss == 1:
		print "Your plugin is potentially vulnerable to XSS. For more informations: https://en.wikipedia.org/wiki/Cross-site_scripting"
		
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
	if xss_detection_beta == True:
		xss(content_file)
	uri_extract(content_file)
	return 0

def uri_extract(content_file):
	string_uri = "Author URI:"
	start = content_file.find(string_uri)
	if start != -1:
		end = content_file.find("\n", start)
		global uri
		uri = content_file[start:end]

