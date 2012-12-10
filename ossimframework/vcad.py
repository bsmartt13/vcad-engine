#!/usr/bin/python
#
# License:
#
#    Copyright (c) 2003-2006 ossim.net
#    Copyright (c) 2007-2011 AlienVault
#    All rights reserved.
#
#    This package is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 dated June, 1991.
#    You may not use, modify or distribute this program under any other version
#    of the GNU General Public License.
#
#    This package is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this package; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#    MA  02110-1301  USA
#
#
# On Debian GNU/Linux systems, the complete text of the GNU General
# Public License can be found in `/usr/share/common-licenses/GPL-2'.
#
# Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
#
import Util, datetime, time, string, math, socket
import InvertedIndex # required to parse host inventory effeciently (without bruteforce).
from Logger import Logger
from OssimDB import OssimDB
from OssimConf import OssimConf
from DBConstantNames import *
from types import *

'''
File: 		vcad.py
Description: 	Vulnerability Correlation And Detection (VCAD) Engine - 
		A Light-weight Vulnerability Scanner
Author:		Bill Smartt <bsmartt13@gmail.com>
Database engineer: Scott Finney
Datastruct engineer: Bin Lu
Class:		Senior Team Project (CS490)
Team:		Tango Down


conventions:
- SQL query strings have names like servicesQuery, vulnerabilitiesQuery, etc
- the results of these queries have names like servicesResults, vulnerabilitiesResults, etc.
- when you loop through a *Results, use `for servicesResult in servicesResults:`
- inside of print statements (for our debugging benefit, we might want to take these out eventually) you will find the following tags:
	[x]: something went wrong.
	[*]: informational. not bad or good, could go either way.
	[+]: good. operation successful, found a match, etc.
	[!]: warning, something might be wrong.
  to add emphasis, tags like [++], [+++], [!!], [xxx], etc. should be used.


SEVERITY:
1 - Serious
2 - High
3 - Medium
4 - <INVALID>
5 - <INVALID>
6 - Low
7 - Info

'''
class vcad:
	def __init__(self):
		# configure logging, databases (alienvault + osvdb)
		self.logger = Logger.logger
		_CONF = OssimConf()
		_OSVDB = "osvdb"
		self._DB = OssimDB(_CONF[VAR_DB_HOST],
				   _CONF[VAR_DB_SCHEMA],
				   _CONF[VAR_DB_USER],
				   _CONF[VAR_DB_PASSWORD])
			
		self._osvdb = OssimDB(_CONF[VAR_DB_HOST],
				      _OSVDB,
				      _CONF[VAR_DB_USER],
				      _CONF[VAR_DB_PASSWORD])
		# connect databases
		avbool = self._DB.connect()
		osvbool = self._osvdb.connect()
		if not avbool:
			self.logger.error("[vcad][x] error connecting to database alienvault")
		if not osvbool:
			self.logger.error("[vcad][x] error connecting to database osvdb")
		self.invertedIndex = InvertedIndex.InvertedIndex()
		self.logger.info("[vcad][+] init complete.")
		return

	# if there is no inverted index on disk, get osvdb data and build it	
	def buildIndex(self):
		alreadyBuilt = self.invertedIndex.loadIndex()
		if alreadyBuilt:
			self.logger.info("[+] inverted index loaded from disk successfully.")
			return
		# first, query osvdb for all the tables of vulnerabilities
		versionsQuery = "SELECT * FROM object_versions;"
		productsQuery = "SELECT * FROM object_products;"
		vendorsQuery = "SELECT * FROM object_vendors;"
		versionResults = self._osvdb.exec_query(versionsQuery)
		productResults = self._osvdb.exec_query(productsQuery)
		vendorResults = self._osvdb.exec_query(vendorsQuery)
		self.logger.info("[vcad] [*] Adding osvdb:object_version to inverted index...")
		for nextVersion in versionResults:
			self.invertedIndex.store(nextVersion['name'], str(nextVersion['id']), "object_versions");
		self.logger.info("[+] done.")
		self.logger.info("[+] Adding osvdb:object_products to inverted index...")
		for nextProduct in productResults:
			self.invertedIndex.store(nextProduct['name'], str(nextProduct['id']), "object_products");
		self.logger.info("[+] done.")
		return

	# lookup: returns a dictionary with two entries: the versionID and productID needed for correlation.
	# do not use this method.  deprecated.
	def lookupBasic(self, product, version):
		self.logger.warn("[!] Warning: vcad.lookupBasic(product, version) is deprecated and should not be used.")
		lookupmsg = "[*] Looking up `" + product + ", " + version + "'..." 
		self.logger.info(lookupmsg)
		productId = self.invertedIndex.search(product)
		versionId = self.invertedIndex.search(version)
		return {'productId': productId, 'versionId': versionId}

	# grab all services for all hosts in ossim, and call parseService() on each host
	def getServices(self):
		resultArray = []
		select = "SELECT hs.service,hi.ip,hs.port,hs.version FROM host_services hs "
		join = "JOIN host_ip hi ON hs.host_id = hi.host_id;"
		servicesQuery = select + join
		self.logger.info("[*] executing query `" + servicesQuery + "`...")
		serviceResults = self._DB.exec_query(servicesQuery);
		for serviceResult in serviceResults:
			nextService = serviceResult['service']
			print "[*] getServices.next:"
			print serviceResult
			result = self.parseService(serviceResult)
			if type(result) is NoneType:
				print "[!] found no vulns for service: " + str(nextService)
				continue #no vulns found, skip
			if len(result) == 0:
				print "[!] found no vulns for service: " + str(nextService)
				continue
			print "[*] result from vcadtest4.lookup(row)"
			print "[*] version: " + str(result['versionId'])
			print "[*] product: " + str(result['productId'])
			unpacked = socket.inet_ntop(socket.AF_INET, serviceResult['ip'])
			print "!!!! unpacked addr: " + unpacked
			nextResult = self.correlate(result['productId'], result['versionId'], str(nextService), serviceResult['port'],unpacked) #serviceResult['ip'])
			print "RETURNED FROM CORRELATE: "
			print nextResult
			if nextResult is None:
				continue
			for item in nextResult:
				resultArray.append(item)
		print "[+] done getServices"
		return resultArray

	# this is the main component of the correlation engine.  Parse the string and try to find a product and version in it.
	def parseService(self, row):
		# these IDs will be used in the table `osvdb:correlations`
		productId = 0; versionId = 0; vendorId = 0
		i = 0
		# bools to keep track of what we have so far.  value always (0 || 1).
		foundProduct = 0; foundVersion = 0; foundVendor = 0
		serviceProto = ""
		nextService = row['service']
		words = nextService.split(" ")
		print nextService
		if ":" in nextService:
			serviceProto = nextService.split(":")[0]	
			words[0] = words[0][len(serviceProto)+1:]
		print words
		if "unknown" in nextService:
			print "[**] found word `unknown' in service, skipping.."
			return #skip looking up things that have the word `unknown'
		currentString = ""; wordCount = 0
		print "len of words list: " + str(len(words))
		for word in words:
			if wordCount >= 1:
				currentString += " "
			currentString += word; wordCount += 1
			print "now trying to find: " + currentString
			indexResult = self.invertedIndex.search(currentString)
			if type(indexResult) is NoneType:
				continue
			if len(indexResult) == 0:
				print "[*] search didn't return anything!, continuing.."
				continue
			print "[*] indexresult for word: " + currentString
			print indexResult
			if ("object_products" in indexResult[0][1]):
				print "[+] new productId " + str(productId)
				foundProduct = 1
				productId = indexResult[0][0]
				currentString = ""; wordCount = 0
			elif ("object_versions" in indexResult[0][1] ):
				print "[+] new versionId " + str(versionId)
				foundVersion = 1
				versionId = indexResult[0][0]
				currentString = ""; wordCount = 0
		if (foundProduct == 1 and foundVersion == 1):
			print "[*] returning: prod: " + str(productId) + " ver " + str(versionId) + "and name: " + row['service']
			return {'productId': productId, 'versionId': versionId, 'name': row['service'], 'proto': serviceProto}
		else:
			print "[!] unable to find the product and version in osvdb for `" + nextService
			return

	# once we have a product and version, do the osvdb correlation.
	def correlate(self, productId, versionId, name, port, ip):
		resultsArray = []
		# entry: {'cve', 'title', 'description', 'solution', }
		ExtRefType = 3 #CVE information is 3rd ext reference
		correlationQuery = "SELECT id FROM object_correlations WHERE object_product_id = %s " %productId
		correlationQuery += "AND object_version_id = %s;" %versionId
		print "[*] executing correlation query"
		print correlationQuery
		correlationId = 0
		correlationResults = self._osvdb.exec_query(correlationQuery)
		print correlationResults
		if len(correlationResults) == 0:
			print "[!!] No results in correlation table!"
			return
		for correlationResult in correlationResults:
			print "[*] next correlation result:"
			correlationId = int(correlationResult['id'])
			print "[+] correlationId found: " + str(correlationId)
			if correlationId == 0:
				print "[-] no correlation id found for productId: " + str(productId) + " and versionId: " + str(versionId)
				return
			# vulnerabilityQuery = "SELECT vulnerability_id FROM object_links WHERE object_correlation_id = " + str(correlationId) + ";"
			vulnerabilityQuery = "SELECT vulnerability_id FROM object_links WHERE object_correlation_id = %s;" %str(correlationId)
			vulnerabilityParams = str(correlationId)
			vulnerabilityResults = self._osvdb.exec_query(vulnerabilityQuery);
			for vulnerabilityResult in vulnerabilityResults:
				vulnerabilityId = int(vulnerabilityResult['vulnerability_id'])
				print "[++] found vulnerability ID"
				# finalQuery = "SELECT * FROM vulnerabilities WHERE id = " + str(vulnerabilityId) + ";"
				finalQuery = "SELECT * FROM vulnerabilities WHERE id=%s;" %str(vulnerabilityId)
				finalResults = self._osvdb.exec_query(finalQuery)
				for finalResult in finalResults:
					extRefsQuery = "SELECT * FROM ext_references WHERE ext_reference_type_id = 3 "
					# extRefsQuery += "AND vulnerability_id = " + str(vulnerabilityId) + ";"
					extRefsQuery += "AND vulnerability_id=%s;" %str(vulnerabilityId)
					extRefsResult = self._osvdb.exec_query(extRefsQuery)
					cvssQuery = "SELECT * FROM cvss_metrics WHERE vulnerability_id =%s;" %str(vulnerabilityId)
					cvssResult = self._osvdb.exec_query(cvssQuery)
					print "\n\nCVSS RESULT:"
					print cvssResult
					if len(cvssResult) == 0:
						cvssResult = []
						cvssResult.append({'score':7.9})
					print "printing finalResult dict"
					for next in finalResult.iterkeys():
						print next + str(finalResult[next])
					print "and now extRefs"
					if len(extRefsResult) > 0:
						for next in extRefsResult[0].iterkeys():
							print next + " " + str(extRefsResult[0][next])
					else:
						extRefsResult.append({'value':"0001-0000"})
					print "[+++] Found CVE-" + extRefsResult[0]['value'] + "\n"
					print "[+++] Title: " + finalResult['title'] + "\n"
					print "[+++] Description: " + finalResult['description'] + "\n"
					print "[+++] Solution: " + finalResult['solution']
					resultsArray.append({'name': name, 'cve':extRefsResult[0]['value'], 'score':cvssResult[0]['score'], 
						'title': finalResult['title'], 'ip': ip, 'port': port, 'description': finalResult['description'],
						'solution': finalResult['solution']})
		return resultsArray
	
	def printResult(self, result):
		print "[+++] Found Vulnerability: " + "\n"
		print "      CVE-" + result['value'] + "\n"
		print "      Title: " + result['title'] + "\n"
		print "      Description: " + result['description'] + "\n"
		print "      Solution: " + result['solution'] + "\n"
		return

	# create the report and the results to go in it.
	def buildReport(self, resultsArray):
		reportId = 0
		if len(resultsArray) == 0:
			print "[-] No results to report.  will not create new report."
		tstamp = self.getTimeStamp()
		print "generating new report (" + tstamp + ")"
		newReportQuery = "INSERT INTO vuln_nessus_reports(name, scantime, report_type, username, failed, results_sent, deleted) "
		newReportQuery += "VALUES('testnewscan', '" + tstamp  + "','V','admin',0,0,0); "
		newReportResult = self._DB.exec_query(newReportQuery)
		confirmReportQuery = "SELECT * FROM vuln_nessus_reports WHERE name='testnewscan';"
		confirmReportResults = self._DB.exec_query(confirmReportQuery)
		print "confirmReportQuery: "
		for thing in confirmReportResults:
			reportId = int(thing['report_id'])
			print "[*] REPORT ID IS NOW: " + str(reportId)
		if reportId == 0:
			print "[x] couldn't create new report or get reportId."
			return
		print resultsArray
		for result in resultsArray:
			message = "<b>CVE-" + result['cve'] + "</b>\n\n"  + "<b>Description:</b> " + result['description'] + "\n\n" + "<b>Solution:</b> " + result['solution']
			message += "\n\n<b>cvss score: " + str(result['score']) + "</b>"
			print message
			message = string.replace(message, "'", " ")
			print "\n\n\n\nmessage after replacement:::"
			print message
			severity = self.calculateSeverity(float(result['score']))
			print "new severity: " + str(severity) + " from cvss: " + str(result['score']) + "\n"
			nextResultQuery = "INSERT INTO vuln_nessus_results(report_id, scantime, record_type, hostIP, service, port, protocol, app, risk, msg) "
			nextResultQuery += "VALUES(" + str(reportId) + ", '" + tstamp +  "', 'V', '" + result['ip'] + "', '" + result['name'] + "', "
			nextResultQuery += str(result['port']) + ", 'tcp', " + "'CVE-"  + result['cve'] 
			nextResultQuery += "', " + str(severity)  +  ", '" + message + "');"
			print "next INSERT: "
			print nextResultQuery
			self._DB.exec_query(nextResultQuery)
		return

	# a crude way to calculate severity.  scales the cvss_metric from 0-10 -> [1, 2, 3, 6] (these are the only valid values for the report results
	def calculateSeverity(self, severity):
		if severity >= 7.5:
			return 1
		elif severity >= 5.0:
			return 2
		elif severity >= 2.5:
			return 3
		else:
			return 6

	def getTimeStamp(self):
		currentDateTime = datetime.datetime.now() # get timestamp, cast to string, chop off microsecs, sanitize punct+ws, return.
		currentDateTimeStr = str(currentDateTime)
		trimMicroseconds = currentDateTimeStr[:19]
		reportTimeStamp = trimMicroseconds.translate(None, string.punctuation).translate(None, string.whitespace)
		print "[+] New timestamp generated: " + reportTimeStamp
		return reportTimeStamp

	# write inverted index to disk if necessary.
	def persist(self):
		successful = self.invertedIndex.serialize()
		if successful:
			return True;
		return False;
		
def main():
	v = vcad()
	v.buildIndex()
	success = v.persist()
	return

if __name__ == '__main__':main()
	
