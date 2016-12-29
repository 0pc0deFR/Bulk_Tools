#!/usr/bin/env python
import sys
import os
import zipfile
import hashlib
import shutil
import string
import random
import platform
import re

# Configuration
tmp_dir = "/tmp/" #Example: /tmp/
log_dir = '/log/' #Example: /log/
ignored_extension = ['.jpg', '.png', '.gif', '.txt', '.md', '.js', '.po', '.mo', '.pot', '.css', '.ttf', '.map', '.svg', '.eot', '.woff', '.woff2'] #You can add your ignored extensions. Files with these extensions will not be audited.
# End Configuration

#Don't modification
uri = None
version_plugin = None
plugin_name = None
log = None
log_filename = None
print_code = None
print_code_type = None
print_classes = None
print_functions_in_class = None
print_construct = None
no_remove_files = None
archive_zip = None
print_user_entries = None
count_xss = count_sqli = count_csrf = count_fi = count_request = 0

def main():
	if len(sys.argv) < 2:
		print "Example: "
		print sys.argv[0] + " file.php [--active-log] [--print-code [XSS,CSRF,FI,SQLI]] [--print-classes [--print-construct]] [--print-user-entries]"
		print sys.argv[0] + " pluginDir [--active-log] [--print-code [XSS,CSRF,FI,SQLI]] [--print-classes [--print-construct]] [--print-user-entries]"
		print sys.argv[0] + " archive.zip [--active-log] [--print-code [XSS,CSRF,FI,SQLI]] [--print-classes [--print-construct]] [--print-user-entries] [--no-remove-files]"
		sys.exit()
	plugin = sys.argv[1]
	arguments(sys.argv)
	if zipfile.is_zipfile(plugin):
		load_archive(plugin)
	else:
		load_plugin(plugin)
	if plugin_name:
		echo(plugin_name)
	if version_plugin:
		echo(version_plugin, '', '')
	if uri:
		echo(uri, '', '')
	global count_xss, count_csrf, count_fi, count_sqli, count_request
	echo("[+] %s possible XSS detected!" % count_xss, '', '\r\n', 'green')
	echo("[+] %s possible CSRF detected!" % count_csrf, '', '', 'green')
	echo("[+] %s possible File Include detected!" % count_fi, '', '', 'green')
	echo("[+] %s possible SQL Injection detected!" % count_sqli, '', '', 'green')
	echo("[+] %s possible REQUEST detected!\r\n" % count_request, '', '', 'green')

def arguments(arguments):
	for val in arguments:
		if val == "--active-log":
			global log
			log = 1
		elif val == "--print-code":
			global print_code
			print_code = 1
			if len(arguments) > arguments.index('--print-code')+1 and  arguments[arguments.index('--print-code')+1] in ['XSS' ,'CSRF', 'FI', 'SQLI']:
				global print_code_type
				print_code_type = arguments[arguments.index('--print-code')+1]
		elif val == "--print-classes":
			global print_classes
			print_classes = 1
		elif val == "--print-construct":
			global print_construct
			print_construct = 1
		elif val == "--no-remove-files":
			global no_remove_files
			no_remove_files = 1
		elif val == "--print-user-entries":
			global print_user_entries
			print_user_entries = 1
	return 0

def version():
	return "V2.18"

def load_archive(plugin):
	global archive_zip
	archive_zip = zipfile.ZipFile(plugin)
	archive_info = zipfile.ZipInfo(plugin)
	hash_dir = hashlib.md5(str(archive_info)).hexdigest()
	archive_zip.extractall(tmp_dir + hash_dir)
	if not os.path.isdir(tmp_dir):
		os.mkdir(tmp_dir)
	echo("The archive as been unpacked in: " + tmp_dir + hash_dir)
	load_plugin(tmp_dir + hash_dir)
	global no_remove_files
	if no_remove_files != True:
		shutil.rmtree(tmp_dir + hash_dir)
		echo("The temporary directory has been removed")

def load_plugin(plugin):
	if os.path.isfile(plugin):
		i = 0
		extension = os.path.splitext(plugin)
		global ignored_extension, no_remove_files, archive_zip
		if not extension[1] in ignored_extension and extension[1] != '':
			if no_remove_files == True or archive_zip == None:
				echo("Audit file: file://" + plugin)
			else:
				echo("Audit file: " + plugin)
			read = load_php(plugin)
			auditing(read)
	elif os.path.isdir(plugin):
		for f in os.listdir(plugin):
			if plugin[len(plugin)-1:] != "/":
				plugin = plugin + "/"
			load_plugin(plugin + f)
	else:
		echo("The file does not exist!")
	

def load_php(plugin):
	if os.path.isfile(plugin):
		open_file = open(plugin,'r')
		reading = open_file.read()
		open_file.close()
		uri_extract(reading)
		version_extract(reading)
		plugin_name_extract(reading)
		reading = remove_comment(reading)
		return reading

def remove_comment(content_file):
	regex = re.compile('(\\/)(\\*).*?(\\*)(\\/)',re.IGNORECASE|re.DOTALL)
	content_file = re.sub(regex, "", content_file)
	regex = re.compile('(\\/)(\\/).*?.\n', re.IGNORECASE|re.DOTALL)
	content_file = re.sub(regex, "", content_file)
	regex = re.compile('(#).*?.\n', re.IGNORECASE|re.DOTALL)
	content_file = re.sub(regex, "", content_file)
	return content_file

def csrf(content_file):
	strings_csrf = ["wp_create_nonce", "wp_verify_nonce", "settings_fields", "wp_nonce_field"]
	start = end = i = csrf = 0
	while True:
		start = content_file.find("<form", end)
		end = content_file.find("</form>", start)
		if start != -1 and end != -1:
			csrf = csrf +1
			while i < len(strings_csrf):
				if content_file.find(strings_csrf[i], start, end) != -1:
					csrf = csrf -1
				i += 1
			i = 0
			echo_code(content_file[start:end+7], '\r\n', '', 'CSRF')
		else:
			break

	if csrf > 0:
		global count_csrf
		count_csrf = count_csrf + csrf
		echo("Your plugin is potentially vulnerable to CSRF with %s entrie(s). For more informations: http://en.wikipedia.org/wiki/Cross-site_request_forgery" % csrf, '\r\n', '', "red")

def xss(content_file):
	strings_xss = ["esc_html", "esc_js", "esc_textarea", "esc_attr", "wp_kses", "htmlspecialchars", "htmlentities", "json_encode"]
	start = end = i = xss = xss_found = 0
	while True:
		start = content_file.find("echo ", end)
		end = content_file.find(";", start)
		if end > content_file.find("?>", start):
			end = content_file.find("?>", start)
		if start != -1 and end != -1 and content_file.find("$", start, end) != -1:
			xss = xss +1
			xss_found = 1
			while i < len(strings_xss):
				if content_file.find(strings_xss[i], start, end) != -1:
					xss = xss -1
					xss_found = 0
				i += 1
			if xss_found == True:
				i = start_var = end_var = 0
				var = content_file[start+5:end]
				while True:
					start_var = content_file.find(var, end_var)
					end_var = content_file.find('\n',start_var)
					if start_var != -1 and end_var != -1:
						while i < len(strings_xss):
							if content_file.find(strings_xss[i], start_var, end_var) != -1:
								xss = xss -1
								xss_found = False
							i += 1
						i = 0
					else:
						break
				if(is_xss(content_file, content_file[start:end]) == True):
					xss = xss -1
				elif xss_found == True:
					echo_code(content_file[start:end], '\r\n', '', 'XSS')
		else:
			break

	if xss > 0:
		global count_xss
		count_xss = count_xss + xss
		echo("Your plugin is potentially vulnerable to XSS with %s entrie(s). For more informations: https://en.wikipedia.org/wiki/Cross-site_scripting" % xss, '\r\n', '', "red")

def sqli(content_file):
	global log
	strings_sqli = ["$wpdb->get_results","$wpdb->query"]
	i = sqli = 0
	while i < len(strings_sqli):
		if content_file.find(strings_sqli[i]) != -1 and content_file.find("$wpdb->prepare") == -1:
			sqli = sqli +1
			start = content_file.find(strings_sqli[i])
			end = content_file.find(";", start)
			while end < content_file.find(")", start):
				end = content_file.find(";", end+1)
			if end > content_file.find("?>", start) and content_file.find("?>", start) != -1:
				end = content_file.find("?>", start)
			echo_code(content_file[start:end], '\r\n', '', 'SQLI')
		i += 1

	if sqli > 0:
		global count_sqli
		count_sqli = count_sqli + sqli
		echo("Your plugin is potentially vulnerable to SQL Injection with %s entrie(s). For more informations: http://en.wikipedia.org/wiki/SQL_injection" % sqli, '\r\n', '', "red")

def file_include(content_file):
	strings_file_include = ["include(", "include_once(", "require(", "require_once("]
	i = start = end = file_include = 0
	while i < len(strings_file_include):
		while True:
			start = content_file.find(strings_file_include[i], end)
			end = content_file.find(");", start)
			if start != -1 and end != -1:
				if content_file.find("$_GET[", start, end) != -1 or content_file.find("$_POST[", start, end) != -1:
					echo_code(content_file[start:end], '\r\n', '', 'FI')
					file_include = file_include +1
			else:
				break
		i += 1

	if file_include > 0:
		global count_fi
		count_fi = count_fi + file_include
		echo("Your plugin is potentially vulnerable to File Inclusion with %s entrie(s). For more informations: http://en.wikipedia.org/wiki/File_inclusion_vulnerability" % file_include, '\r\n', '', "red")

def request(content_file):
	request = start = end = 0
	strings_request = ["$_REQUEST"]
	for string_request in strings_request:
		while True:
			start = content_file.find(string_request, end)
			end = start+1
			if start != -1:
				request = request +1
			else:
				break

	if request > 0:
		global count_request
		count_request = count_request + request
		echo("Your plugin is potentially vulnerable to Request with %s entrie(s). For more informations: http://php.net/manual/en/reserved.variables.request.php" % request, '\r\n', '', "red")

def auditing(content_file):
	list_classes(content_file)
	csrf(content_file)
	sqli(content_file)
	xss(content_file)
	file_include(content_file)
	request(content_file)
	deprecated_php(content_file)
	user_entries(content_file)

def user_entries(content_file):
	global print_user_entries
	if print_user_entries == True:
		strings_user_entries = ["$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_FILES"]
		i = 0
		for string_user_entries  in strings_user_entries:
			if content_file.find(string_user_entries) != -1:
				echo("%s are detected" % string_user_entries, '', '', 'blue')
			i +=1

def uri_extract(content_file):
	string_uri = "Author URI:"
	start = content_file.find(string_uri)
	if start != -1:
		global uri
		end = content_file.find("\n", start)
		uri = content_file[start:end]

def version_extract(content_file):
	string_version = "Version:"
	start = content_file.find(string_version)
	if start != -1:
		global version
		end = content_file.find("\n", start)
		version = content_file[start:end]

def plugin_name_extract(content_file):
	string_plugin_name = "Plugin Name:"
	start = content_file.find(string_plugin_name)
	if start != -1:
		global plugin_name
		end = content_file.find("\n", start)
		plugin_name = content_file[start:end]

def deprecated_php(content_file):
	php5_3 = [["call_user_method(","call_user_func()"], ["call_user_method_array(", "call_user_func_array()"], ["define_syslog_variables(", "undefined function"], ["dl(", "undefined function"], ["ereg(", "preg_match()"], ["ereg_replace(", "preg_replace()"], ["eregi(", "preg_match()"], ["eregi_replace(", "preg_replace()"], ["set_magic_quotes_runtime(", "magic_quotes_runtime()"], ["session_register(", "undefined function"], ["session_unregister(", "undefined function"], ["session_is_registered(", "undefined function"], ["set_socket_blocking(", "stream_set_blocking()"], ["split(", "preg_split()"], ["spliti(", "preg_split()"], ["sql_regcase(", "undefined function"], ["mysql_db_query(", "mysql_select_db() and mysql_query()"], ["mysql_escape_string(", "mysql_real_escape_string()"]]
	php5_4 = [["mcrypt_generic_end(", "undefined function"], ["mysql_list_dbs(", "undefined function"]]
	php5_5 = [["setTimeZoneID(", "setTimeZone()"], ["datefmt_set_timezone_id(", "datefmt_set_timezone()"], ["mcrypt_cbc(", "undefined function"], ["mcrypt_cfb(", "undefined function"], ["mcrypt_ecb(", "undefined function"], ["mcrypt_ofb(", "undefined function"]]
	filters_char = [" ", "("]
	i = 0
	while i < len(php5_3):
		if(content_file.find(php5_3[i][0]) != -1 and content_file.find(php5_3[i][1][0:-1]) == -1 and filter(content_file[content_file.find(php5_3[i][0])-1:content_file.find(php5_3[i][0])], filters_char) == True):
			echo("PHP optimization: You are using deprecated function: %s) is replaced by %s" % (php5_3[i][0], php5_3[i][1]), '\r\n', '', "blue")
		i = i+1
	i = 0
	while i < len(php5_4):
		if(content_file.find(php5_4[i][0]) != -1 and content_file.find(php5_4[i][1][0:-1]) == -1 and filter(content_file[content_file.find(php5_4[i][0])-1:content_file.find(php5_4[i][0])], filters_char) == True):
			echo("PHP optimization: You are using deprecated function: %s) is replaced by %s" % (php5_4[i][0], php5_4[i][1]), '\r\n', '', "blue")
		i = i+1
	i = 0
	while i < len(php5_5):
		if(content_file.find(php5_5[i][0]) != -1 and content_file.find(php5_5[i][1][0:-1]) == -1 and filter(content_file[content_file.find(php5_4[i][0])-1:content_file.find(php5_4[i][0])], filters_char) == True):
			echo("PHP optimization: You are using deprecated function: %s) is replaced by %s" % (php5_5[i][0], php5_5[i][1]), '\r\n', '', "blue")
		i = i+1

def list_classes(content_file):
	global print_classes
	if print_classes != True:
		return False
	end = 0
	filters_char = ["*/", "//", "#"]
	while True:
		start = content_file.find("class ", end)
		end = content_file.find("{", start)
		if(start != -1 and end != -1 and filter(content_file[start:end], filters_char) == False and re.match("^[a-zA-Z]",content_file[start+6:start+7])):
			echo("The %s class was detected" % content_file[start+6:end].rstrip(), '', '', "blue")
			construct_in_class(content_file, end)
		else:
			break

def construct_in_class(content_file, starter):
	global print_construct
	if print_construct != True:
		return False
	start = content_file.find("function __construct(", starter)
	end = content_file.find(")", start)
	if start == -1:
		echo("No constructor has been found", '', '', "blue")
	else:
		echo("The constructor of the class is %s" % content_file[start+9:end+1], '', '', "blue")

def filter(character, filters_char):
	for filter_char in filters_char:
		if character == filter_char:
			return True
		elif character.find(filter_char) != -1:
			return True
	return False

def is_xss(content_file, vulnerable):
	if(is_exception(content_file, vulnerable) == True):
		return True

def is_exception(content_file, vulnerable):
	start = vulnerable.find("$")
	end = vulnerable.find("->")
	if(content_file.find("Exception " + vulnerable[start:end]) != -1):
		return True

def log_rand_name():
	len_name = 15
	i = 0
	name = random.choice(string.letters)
	while i != len_name:
		name = name + random.choice(string.letters)
		i = i + 1
	return name

def echo(string, crlf = "\r\n", crlf_print = '\r\n', color_print = "default"):
	global log_filename, log_dir, log
	if platform.system() == "Linux" and color_print != "default":
		if color_print == "blue":
			print crlf_print + "\033[94m" + string.strip() + "\033[0m"
		elif color_print == "red":
			print crlf_print + "\033[91m" + string.strip() + "\033[0m"
		elif color_print == "green":
			print crlf_print + "\033[93m" + string.strip() + "\033[0m"
	else:
		print crlf_print + str(string).strip()
	if log:
		if not log_filename:
			log_filename = log_rand_name() + '.txt'
			print "\nYour file log is " + log_filename
		if not os.path.isdir(log_dir):
			os.mkdir(log_dir)
		if not os.path.isfile(log_dir + log_filename):
			crlf = ''
		file_log_open = open(log_dir + log_filename, 'a+')
		file_log_open.write(crlf + string.strip())
		file_log_open.close()

def echo_code(string, crlf = '\r\n', crlf_print = '\r\n', exploit_type = ''):
	global print_code, print_code_type
	if (print_code and print_code_type != None and print_code_type == exploit_type) or print_code and print_code_type == None :
		echo(string, crlf, crlf_print)
