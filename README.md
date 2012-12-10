http://bsmartt13.github.com/vcad-engine/

## Vulnerability Correlation and Detection Engine (VCAD) for OSSIM

VCAD is a lightweight vulnerability scanner which is intended for use inside of [Alienvault](http://alienvault.com/)'s [OSSIM](http://communities.alienvault.com/indexc.html?utm_expid=61134069-1).

The idea of this project is to decouple Network probing from analysis in vulnerability scanning.  OSSIM is constantly probing the network for hosts with NMAP.  VCAD takes advantage of this continuously incoming information by doing correlation between it and a vulnerability database (a local copy of OSVDB). 

Due to the lack of network probing VCAD is fast.  The time it takes to run VCAD is a direct result of algorithmic complexity (not network latency).  

Currently, VCAD is designed to work within OSSIM.  However, abstracting VCAD out of OSSIM is within the realm of possibility and something we are interested in.

To use VCAD, get the repository and add the files to the following folders:
***


**github repo**  	---->	**ossim directory**

ossimframework/*.py	---->	/usr/share/ossim-framework/ossimframework/

vulnmeter/sched.php	---->	/usr/share/ossim/www/vulnmeter/

conf/main.php		---->	/usr/share/ossim/www/conf/

netscan/index.php	---->	/usr/share/ossim/www/netscan/

netscan/do_scan.php	---->	/usr/share/ossim/www/netscan/


***


Project authors:
Bill Smartt <bsmartt13>
Scott Finney
Bin Lu