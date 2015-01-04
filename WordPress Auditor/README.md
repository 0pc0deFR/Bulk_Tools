# WordPress Auditor

## Changelog
Version 2.18: Add REQUEST Detection  
Version 2.17: Improving the comments suppression function  
Version 2.16: Add print-constuct function and add link in filename  
Version 2.15: Fix another bug in PHP deprecated functions detection and add optional print detected classes  
Version 2.14: Fix bug in PHP deprecated functions detection  
Version 2.13: Add Exception verification in XSS Detection  
Version 2.12: Add syntax coloration  
Version 2.11: Add print-code function  
Version 2.10: Add counters  
Version 2.9: Fix bug  
Version 2.8: Optimization in log function and add File Inclusion Detection  
Version 2.7: Optimization in "Ignored Extensions" and add version/plugin_name extraction and fix bug in XSS Detection  
Version 2.6: Add log option and optimization in XSS Detection  
Version 2.5: Add "Ignored Extensions" and fix multiple bugs  
Version 2.4: Add XSS Detection  
Version 2.3: Support format zip archive  
Version 2.2: Support multiple or single file  
Version 2.1: Multiple bug fixes and optimization in CSRF Detection  
Version 2.0: Add CSRF Detection  
Version 1.0: Creation, Support SQL Injection Detection  

## How to use
WordPress Auditor require Python 2.6 or Python 2.7: http://www.python.org/download/
Download lib_wordpress_auditor.py and wordpress_auditor.py in directory.
Configure in lib_wordpress_auditor.py the "tmp_dir" wich must be a temporary directory, "log_dir" wich must be a log directory and "ignored_extension" for add a ignored extensions to analyze. Caution: The user who executes wordpress_auditor must have read/write permissions for the temporary directory and log directory.
wordpress_auditor to execute command line.

### Linux
```
cd WORDPRESS_AUDITOR_DIRECTORY

python wordpress_auditor.py

Wordpress Auditor V2.16
Kevin Falcoz (aka 0pc0deFR)
Twitter: @0pc0deFR - Mail: 0pc0deFR@gmail.com
License GPL
Example: 
wordpress_auditor.py file.php [--active-log] [--print-code] [--print-classes [--print-construct]]
wordpress_auditor.py pluginDir [--active-log] [--print-code] [--print-classes [--print-construct]]
wordpress_auditor.py archive.zip [--active-log] [--print-code] [--print-classes [--print-construct]] [--no-remove-files]
```

### Windows
```
cd WORDPRESS_AUDITOR_DIRECTORY
python.exe wordpress_auditor.py

Wordpress Auditor V2.16
Kevin Falcoz (aka 0pc0deFR)
Twitter: @0pc0deFR - Mail: 0pc0deFR@gmail.com
License GPL
Example: 
wordpress_auditor.py file.php [--active-log] [--print-code] [--print-classes [--print-construct]]
wordpress_auditor.py pluginDir [--active-log] [--print-code] [--print-classes [--print-construct]]
wordpress_auditor.py archive.zip [--active-log] [--print-code] [--print-classes [--print-construct]] [--no-remove-files]
```

## Support
Wordpress Auditor detects the Wordpress API for safe SQL requests or GET/POST requests but if the API is not detected Wordpress Auditor indicate a potential vulnerability.
Wordpress Auditor is developed to be versatile because if you use your own API you can add in "strings_csrf" or "string_xss" your API for GET/POST requests and replace content_file.find("$wpdb->prepare") by your API (only "$wpdb->prepare") for SQL requests.
Wordpress Auditor detect multiple vulnerabilities: XSS, SQL Injection and CSRF to Wordpress plugin.

##Online Tool
http://0pc0defr.fr/wp-check/index.php
