#!/bin/bash

# File:		remove-vcad.sh
# Author:	Bill Smartt <bsmartt13@gmail.com>
# Desc:		script to automatically remove vcad from OSSIM.

echo "[*] removing vcad-engine python files from '/usr/share/ossim-framework/ossimframework/' ..."
rm /usr/share/ossim-framework/ossimframework/vcad*
rm /usr/share/ossim-framework/ossimframework/InvertedIndex.*
echo "[+] done."

echo "[*] restoring UI integration files..."
mv /usr/shar/ossim/www/conf/main.php.old /usr/share/ossim/www/conf/main.php
mv /usr/shar/ossim/www/vulnmeter/sched.php.old /usr/share/ossim/www/vulnmeter/sched.php
mv /usr/shar/ossim/www/netscan/index.php.old /usr/share/ossim/www/netscan/index.php
mv /usr/shar/ossim/www/netscan/do_scan.php.old /usr/share/ossim/www/netscan/do_scan.php
echo "[+] done."

echo "[+] vcad removed successfully."
echo "[+] Thanks for using vcad. :)"
