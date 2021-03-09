#!/usr/bin/env python
import sys,csv,time,argparse
from datetime import datetime,timedelta
from math import sqrt
from csv import writer

def main(argv):
     try:
          parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,description='Script to extract cps information for the firewall')
          parser.add_argument('-i','--interface',nargs='?',default=argparse.SUPPRESS,help='Interface for which cps needs to be calculated')
          parser.add_argument('-z','--zone',nargs='?',default=argparse.SUPPRESS,help='Ingress Zone for which cps needs to be calculated')
          parser.add_argument('-p','--protocol',nargs='?',choices=['tcp', 'udp', 'icmp','other','all','any'],default='all',help='Protocol for which cps needs to be calculated. By default we calculate cps for udp/tcp and icmp')
          parser.add_argument('-t','--interval',nargs='?',default='1',help='Polling interval to collect statistics')
          parser.add_argument('-l','--lowcps',nargs='?',default='1',help='Minimum cps value for an interval to be considered. Anything lower will be ignored for threshold calculation.')
          parser.add_argument('-c','--highcps',nargs='?',default='10000',help='Maximum cps value for an interval to be considered. Anything higher will be ignored for threshold calculation.')
          parser.add_argument('-s','--suppress',nargs='?',default='true',help='Suppress logging for every epoch interval.')
          parser.add_argument('-f','--filename',nargs='?',default='log.csv',help='File name including the full path if not residing in the script dir.')
          
          values = vars(parser.parse_args())
          intf = ""
          zone = ""
          if 'interface' in values:
               intf = values['interface']
          if 'zone' in values:
               zone = values['zone']
          proto = values['protocol']
          sstr = values['interval']
          lowcps = values['lowcps']
          highcps = values['highcps']
          suppress = values['suppress']
          fname = values['filename']

          result = []
          resultz = []
 
          with open(fname, 'r') as csvfile:
               reader = csv.DictReader(csvfile)
               lreader = list(reader)
               for row in range(len(lreader)):
                    if proto == "all":
                         if lreader[row]['Inbound Interface'] == intf:
                               result.append(lreader[row])
                         if lreader[row]['Source Zone'] == zone:
                               resultz.append(lreader[row])
                    if proto == "tcp":
                         if lreader[row]['Inbound Interface'] == intf and lreader[row]['IP Protocol'] == "tcp":
                               result.append(lreader[row])
                         if lreader[row]['Source Zone'] == zone and lreader[row]['IP Protocol'] == "tcp":
                               resultz.append(lreader[row])
                    if proto == "udp":
                         if lreader[row]['Inbound Interface'] == intf and lreader[row]['IP Protocol'] == "udp":
                               result.append(lreader[row])
                         if lreader[row]['Source Zone'] == zone and lreader[row]['IP Protocol'] == "udp":
                               resultz.append(lreader[row])
                    if proto == "icmp":
                         if lreader[row]['Inbound Interface'] == intf and lreader[row]['IP Protocol'] == "icmp":
                               result.append(lreader[row])
                         if lreader[row]['Source Zone'] == zone and lreader[row]['IP Protocol'] == "icmp":
                               resultz.append(lreader[row])
                    if proto == "other":
                         if lreader[row]['Inbound Interface'] == intf and (lreader[row]['IP Protocol'] != "tcp" and lreader[row]['IP Protocol'] != "udp" and lreader[row]['IP Protocol'] != "icmp"):
                               result.append(lreader[row])
                         if lreader[row]['Source Zone'] == zone and (lreader[row]['IP Protocol'] != "tcp" and lreader[row]['IP Protocol'] != "udp" and lreader[row]['IP Protocol'] != "icmp"):
                               resultz.append(lreader[row])
          
          s = int(sstr)
          sec = timedelta(seconds=s)             
          FMT = "%Y/%m/%d %H:%M:%S"

          if len(result):
               print ("CPS Stats for interface= " + intf + " and protocol= " + proto)
               nel = sorted(result, key=lambda k: k['Start Time'],reverse=True)             
               bucket = 1
               cpslist = []
     
               for row in range(len(nel)):
                    if nel[row]['Inbound Interface'] != "0":
                            t1 = nel[row]['Start Time']
                            count = 0
                            t1_tup = datetime.strptime(t1,FMT)
                            for secrow in range(len(nel)):
                                    if nel[secrow]['Inbound Interface'] != "0":
                                            t2 = nel[secrow]['Start Time']
                                            t2_tup = datetime.strptime(t2,FMT)
                                            diff = t1_tup - t2_tup 
                                            if diff <= sec/2:
                                                    count = count + 1
                                                    nel[secrow]['Inbound Interface'] = "0"
                            cps = count/s
                            if (int(cps) > int(lowcps)) and (int(cps) < int(highcps)):
                              cpslist.append(cps)
                              if suppress != 'true':
                                   print ("**" + str(bucket) + "(" + t1 + "): cps is " + str(cps))
                            else:
                              if suppress != 'true':
                                   print (str(bucket) + "(" + t1 + "): cps is " + str(cps))
                            bucket = bucket + 1
               calc_stats(cpslist,'interface= '+intf)
                            
          if len(resultz):
               print ("CPS Stats for zone= " + zone + " and protocol= " + proto)
               nelz = sorted(resultz, key=lambda k: k['Start Time'],reverse=True)             
               bucket = 1
               cpslistz = []
     
               for row in range(len(nelz)):
                    if nelz[row]['Source Zone'] != "0":
                            t1 = nelz[row]['Start Time']
                            count = 0
                            t1_tup = datetime.strptime(t1,FMT)
                            for secrow in range(len(nelz)):
                                    if nelz[secrow]['Source Zone'] != "0":
                                            t2 = nelz[secrow]['Start Time']
                                            t2_tup = datetime.strptime(t2,FMT)
                                            diff = t1_tup - t2_tup 
                                            if diff <= sec/2:
                                                    count = count + 1
                                                    nelz[secrow]['Source Zone'] = "0"
                            cps = count/s
                            if int(cps) > int(lowcps) and (int(cps) < int(highcps)):
                              cpslistz.append(cps)                     
                              if suppress != 'true':
                                   print ("**" + str(bucket) + "(" + t1 + "): cps is " + str(cps))
                            else:
                              if suppress != 'true':
                                   print (str(bucket) + "(" + t1 + "): cps is " + str(cps))                              
                            bucket = bucket + 1
               calc_stats(cpslistz,'zone= '+zone)

     except KeyboardInterrupt:
          print ('Interrupted')
          sys.exit(0)
     except IOError as io:
          print ("Error Opening file: "+fname, io)


def calc_stats(lst,intf):
     print ("Max cps for " + intf + " is= " + str(max(lst)))
     mean = sum(lst)/len(lst)
     print ("Avg cps for " + intf + " is= " + str(mean) + "\n")
     differences = [x - mean for x in lst]
     sq_differences = [d ** 2 for d in differences]
     ssd = sum(sq_differences)
     variance = ssd/len(lst)
     sd = sqrt(variance)
     print ("Standard Deviation for " + intf + " is= " + str(sd) + "\n")
     rec_thresholds(max(lst),mean,sd)

def rec_thresholds(peak,mean,sd):
     print ("********** Suggested Threshold Values **********")
     print ("Alert Threshold = " + str(mean+sd))
     print ("Activate Threshold = " + str(1.1 * float(peak)))
     print ("Max Threshold = " + str(1.1 * 1.1 * float(peak)))
     row_contents = [str(mean+sd),str(1.1 * float(peak)),str(1.1 * 1.1 * float(peak))]
     append_csv_row('output.csv', row_contents)

def append_csv_row(file_name, list_of_items):
    with open(file_name, 'a+', newline='') as write_obj:
        csv_writer = writer(write_obj)
        csv_writer.writerow(list_of_items) 

if __name__ == "__main__":
   main(sys.argv[1:])          