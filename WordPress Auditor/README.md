# WordPress Auditor

## Changelog
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
Configure in lib_wordpress_auditor.py the "tmp_dir" wich must be a temporary directory. Caution: The user who executes wordpress_auditor must have read/write permissions for the temporary directory.
Wordpress_auditor to execute command line.

### Linux
```
cd WORDPRESS_AUDITOR_DIRECTORY

python wordpress_auditor.py

Wordpress Auditor V2.3
Kevin Falcoz (aka 0pc0deFR)
Twitter: @0pc0deFR - Mail: 0pc0deFR@gmail.com
License GPL
Example: 
wordpress_auditor.py file.php
wordpress_auditor.py pluginDir
wordpress_auditor.py archive.zip
```

### Windows
```
cd WORDPRESS_AUDITOR_DIRECTORY
python.exe wordpress_auditor.py

Wordpress Auditor V2.3
Kevin Falcoz (aka 0pc0deFR)
Twitter: @0pc0deFR - Mail: 0pc0deFR@gmail.com
License GPL
Example: 
wordpress_auditor.py file.php
wordpress_auditor.py pluginDir
wordpress_auditor.py archive.zip
```

## Support
Wordpress Auditor detects the Wordpress API for safe SQL requests or GET/POST requests but if the API is not detected Wordpress Auditor indicate a potential vulnerability.
Wordpress Auditor is developed to be versatile because if you use your own API you can add in "strings_csrf" your API for GET/POST requests and replace content_file.find("$wpdb->prepare") by your API (only "$wpdb->prepare") for SQL requests.
