#!/bin/bash

# File:		install-vcad.sh
# Author:	Bill Smartt <bsmartt13@gmail.com>
# Desc:		script to automatically install vcad and build lookup tables.

echo "[*] moving vcad-engine python files to '/usr/share/ossim-framework/ossimframework/' ..."
mv vcad.py /usr/share/ossim-framework/ossimframework/
mv InvertedIndex.py /usr/share/ossim-framework/ossimframework/
mv vcadDriver.py /usr/share/ossim-framework/ossimframework/
echo "[+] done."

echo "[*] backing up UI integration files..."
mv /usr/share/ossim/www/conf/main.php /usr/share/ossim/www/conf/main.php.old
mv /usr/share/ossim/www/vulnmeter/sched.php /usr/share/ossim/www/vulnmeter/sched.php.old
mv /usr/share/ossim/www/netscan/index.php /usr/share/ossim/www/netscan/index.php.old
mv /usr/share/ossim/www/netscan/do_scan.php /usr/share/ossim/www/netscan/do_scan.php.old
echo "[+] done."

echo "[*] moving UI integration files..."
mv main.php /usr/share/ossim/www/conf/main.php
mv sched.php /usr/share/ossim/www/vulnmeter/sched.php
mv index.php /usr/share/ossim/www/netscan/index.php
mv do_scan.php /usr/share/ossim/www/netscan/do_scan.php
echo "[+] done."

echo "[*] building inverted index..."
python /usr/share/ossim-framework/ossimframework/vcad.py
echo "[+] done."
echo "[++] setup complete.  vcad should now be available as a vulnerability scanner in OSSIM settings -> advanced -> vulnerability scanner""
