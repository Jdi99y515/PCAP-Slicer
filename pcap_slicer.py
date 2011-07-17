#!/usr/bin/env python
# encoding: utf-8
"""
pcap_slicer.py

Created by Scott J. Roberts on 2010-07-24.
Copyright (c) 2010 twosixnine. All rights reserved.
"""

import sys
import getopt
import os
import re
import time
from datetime import datetime


help_message = '''
Usage: pcap_slicer.py [-s <start time (hh:mm:ss)> ] [-e <end time (hh:mm:ss)] [-S <source ip>] [-D <destination ip>] [-h] [-o <alternate output>]
Help: Finds activity in a directory full of PCAPs and unifies the activity in a single PCAP.

Options: 
      -s, --start       Start Time: The time to begin the PCAP slice at. (Format: hh:mm:ss)
      -e, --end         End Time: The time to end the PCAP slice at. (Format: hh:mm:ss)
      -S, --src         The desired source IP addgress.
      -D, --dest        The desired destination IP address.
      -h, --help        Prints this help information.
      -o, --output      Blocks until the used applications are closed (even if they were already running).

PCAP Gathering Command: "tcpdump -i <interface> -vvvXSs <snap length> -G <seconds per pcapfile> -w pcap_%s.pcap" 
      
~ Questions? Ask Mentat. Compliments? Tell Mentat. Complaints? Punch Bacon. ~
'''

cal_date = '20100730'

mergecap_path = '/bin/mergecap'
tcpdump_path = '/usr/sbin/tcpdump'

pcap_repo = '/pcaps/'
intermediate_pcap_repo = pcap_repo + 'intermediate/'
final_pcap_repo = pcap_repo + 'final/'

class PCAPSlicer():
	def __init__(self):
		pass
	
	def build_filter(self, sip, dip):
		"""
		This should be my doc string
		"""
		
		if sip:
			sip_filter = 'ip host ' + sip + ' '
		
		if dip:
			dip_filter = 'ip host ' + dip + ' '
			
		if sip and dip:
			tcpdump_filter = sip_filter + ' and ' + dip_filter
			
			return tcpdump_filter
		else:
			return sip_filter		
	
	def pcap_merge(self, pcaps, output_name):
		if len(pcaps) == 1:
			return 1
		
		mergers = ""
		
		for pcap in pcaps:
			mergers += pcap + ' '
		
		output_file = '%sintermediate-%s ' % (intermediate_pcap_repo, output_name)
		
		command_string = mergecap_path + ' -w %s ' % (output_file) + mergers
		
		try:
			os.system(command_string)
		except:
			print "FAIL!"
			output_file = None
		finally:
			return output_file
		
		
	
	def pcap_cut(self, stime, etime, sip=None, dip=None, dir=pcap_repo):
		"""
		This is the workhorse function. Given a time, date
		"""
		
		output_name = "%s\-%s\ %s\<\-\>%s\.pcap" % (stime, etime, sip,dip)
		
		intermediate_file = self.pcap_merge(self.pcap_time_finder(stime, etime), output_name)
		
		print "Intermediate File: %s" % intermediate_file
		
		final_file = self.pcap_ip_cut(intermediate_file, sip, dip, output_name)
		
		print "Final File: %s" % final_file
	
	def convert_from_epoch_time(self, e_time):
		"""
		I don't work yet.
		"""
		return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(e_time))
	
	def convert_to_epoch_time(self, hr_time):
		#formatted_time = datetime.strftime(datetime.strptime('20100729 %s' % (time), '%Y%m%d %H:%M:%S'), '%Y%m%d %H:%M:%S')
		#print formatted_time 
		#split = time.split(':')
		#int(time.mktime('')) - time.timezone
		
		date_time = '%s %s' % (cal_date, hr_time)
		pattern = pattern = '%Y%m%d %H:%M:%S'
		epoch = int(time.mktime(time.strptime(date_time, pattern)))
		return epoch
	
	def pcap_time_finder(self, stime='00:00:00', etime='99:99:99', pcap_dir=pcap_repo):
		"""
		Switch to epoch time.
		"""
		
		valid_files = []
				
		for file in os.listdir(pcap_dir):
			file_ext = os.path.splitext(file)
			if file_ext[1] == '.pcap':
				file_time = file_ext[0].split('_')[1].split(':')
				
				if int(self.convert_to_epoch_time(stime)) < int(file_time[0]) < int(self.convert_to_epoch_time(etime)):
					valid_files.append(file)
				
		return valid_files
	
	def pcap_ip_cut(self, intermediate_pcap, sip, dip, output_name):
		"""
		Uses TCP dump to take a PCAP, 
		"""
		
		final_pcap_path = final_pcap_repo + output_name
		
		command_string = tcpdump_path + " -q -r %s -w %s %s" % (intermediate_pcap, final_pcap_path, self.build_filter(sip, dip))
				
		try:
			os.system(command_string)
			output_file = final_pcap_path
		except:
			print "FAIL!"
			output_file = None
		
		return output_file
	


class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

#class TrafficNotFound(Excpetion):
#	def __init__(self.msg):
#		self.msg = msg


def verify_ip(ip):
	parts = ip.split(".")
		
	if len(parts) != 4:
		return False
		
	for item in parts:
		if not 0 <= int(item) <= 255:
			return False
			
	return ip

def verify_time(time):
	parts = time.split(":")
		
	if len(parts) != 3:
		return False
		
	if not 0 <= int(parts[0]) <= 24:
			return False	
	if not 0 <= int(parts[1]) <= 60:
			return False
	if not 0 <= int(parts[2]) <= 60:
			return False
		
	return time


def main(argv=None):	
	if argv is None:
		argv = sys.argv
	try:
		try:
			opts, args = getopt.getopt(argv[1:], "s:e:S:D:ho:v", ["start=", "end=", "src=", "dest=", "help", "output="])
		except getopt.error, msg:
			raise Usage(msg)
		
		# option processing
		for option, value in opts:
			
			# Time Methods
			if option in ("-s", "--start"):
				stime = verify_time(value)
			if option in ("-e", "--end"):
				etime = verify_time(value)
			
			# IP Methods
			if option in ("-S", "--src"):
				sip = verify_ip(value)
			if option in ("-D", "--dest"):
				dip = verify_ip(value)
			
			# Extra Methods
			if option in ("-h", "--help"):
				raise Usage(help_message)
			if option in ("-o", "--output"):
				output = value
			else:
				output = "output.pcap"
			if option == "-v":
				verbose = True
		
		if not stime or not etime:
			raise Usage('A vaild start and end Time are required.')
		elif not sip or not dip:
			raise Usage('A vaild source and desintation ip are required.')
		else:
			p = PCAPSlicer()
			p.pcap_cut(stime, etime, sip, dip)
					
	#except TrafficNotFound, err:
	#	print >> sys.stderr, "Traffic between %s and %s not found in any pcap collected between %s and %s." % (sip, dip, stime, etime)
	#	return 2
	except Usage, err:
		print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
		print >> sys.stderr, "\t for help use --help"
		return 2
	except:
		print >> sys.stderr, "\t for help use --help"
		return 2



def main_test(argv=None):
	p = PCAPSlicer()
	print p.pcap_cut("10:33:40", "10:45:40", '192.168.0.130', '224.0.0.251')

if __name__ == "__main__":
	sys.exit(main())
