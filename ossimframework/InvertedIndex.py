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

'''
Created on 29 Sep,2012

Author: Bin Lu

converted to OOP by Bill Smartt - 10/20/12
Write index to file / persistant data storage by Bill Smartt - 10/20/12
'''

# we need os to do File I/O, cPickle for serialization (cPickle is a faster more secure implementation of pickle).
import os, cPickle as pickle
from Logger import Logger
class InvertedIndex:
	def __init__(self):
		self.logger = Logger.logger
		self.index = {}
		self.picklename = "vcad.pkl"
		self.isPickled = False;

	# used to build the index.  store a single row of < object_{products|versions} in index.
	# <K,V>: <{product|version}, tablename> (ie <Apache httpd, object_products>)
	def store(self, text, id, tableName):
		idList = {}
		text = text.lower()
		count = 1
		if len(text) > 0:
			if(self.index.has_key(text)):
				idList = self.index[text]
				if(idList.has_key(id)):
					positionList = idList[id]
					positionList.append(str(count))
					comboList = [tableName, positionList]
					idList[id] = comboList
				else:	# idList doesn't already have key
					positionList = []
					positionList.append(str(count))
					comboList = [tableName, positionList]
					idList[id] = comboList
			else:   # index doesn't already have key
				idList = {}
				positionList = []
				positionList.append(str(count))
				comboList = [tableName, positionList]
				idList[id] = comboList
                
			self.index[text] = idList # add to index
			count+=1
		return

	# standard inverted index lookup.
	def search(self, query):
		if not query:
			return
		results = []
		query = query.lower()
		if(self.index.has_key(query)):
			localResult = self.index[query]
			for key in localResult.keys():
				localResultValue = localResult[key]
				tableName = localResultValue[0]
				subResult = []
				subResult.append(key)
				subResult.append(tableName)
				results.append(subResult)
		return results

	## the serialize interface begins here ##
	# write inverted index to file
	def serialize(self):
		if os.path.exists(self.picklename):
			self.logger.warn("[!] trying to overwrite pickled index.  try update(self).")
			return False;
		if len(self.index) == 0:
			self.logger.warn("[!] trying to pickle an empty index.  use store() first.")
			return False;
		# at this point we're ready to pickle.
		pickle.dump(self.index, open(self.picklename, "wb"))
		logger.info("[+++] pickle dump complete.")
		return True;
	# load inverted index from file if it exists.
	# if !exists, we will build it.
	def loadIndex(self):
		if not os.path.exists(self.picklename):
			picklemsg = "[!] pickled file `" + self.picklename + "` not found!"
			self.logger.warn(picklemsg)
			return False;
		self.index = pickle.load( open(self.picklename, "rb"))
		self.logger.info("[+++] picle load complete.")
		return True;
	## end of serialize interface ##
