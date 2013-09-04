#!/usr/bin/python
"""
Gathers system information useful for diagnosing issues related to OS tier and
ArcSight connector level issues.

__author__ = "Adam Reber"
__email__ = "adam.reber@gmail.com"
__version__ = "0.9"
__date__ = "09/04/2013"
__status__ = "Development"


History:
    0.1 (09/13/2012) - Initial version
    0.2 (09/19/2012) - Added native grep-like function
    0.3 (10/16/2012) - Changed how connectors are detected, should now find all arcsight
                       connectors under /, even if they are not installed as a service.
    0.4 (02/05/2013) - Modified to use class structure rather than dictionaries
    0.5 (05/09/2013) - Added connector-type specific attributes
    0.6 (05/13/2013) - Added support for exporting data to pickled file (later removed)
    0.7 (05/23/2013) - Included failovers in destinations for connectors
    0.8 (08/13/2013) - Improved support for Python 2.4
    0.9 (09/04/2013) - Cleaned up, added output format options

Future:
    - Support for multiple output formats (XML,CEF,CSV,JSON,etc)
    - Output logging
    - Additional connector details based on type of connector
      - Syslog: Listening port
      - FlexConnector: Flex file details (MD5, time created)
      - Oracle: DB connection info
    - Send data to another server for central collection
    - Config file to choose options
    - Server stats:
        - Zombie Processes
        - System date / timezone

"""

import os,sys,httplib,subprocess,re,time,glob,socket
from datetime import datetime

###########################################
#     OPERATING SYSTEM INFO FUNCTIONS     #
###########################################
def runOSCommand(command):
    """
     Description: Run a command from the shell, return the output of the command as a string
           Input: Command to run, with appropriate escape characters
          Output: The output of the command that was run.
    """
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = process.stdout.read()
    error = process.stderr.read()
    process.stdout.close()
    process.wait()
    if error:
        return "<Unknown (ERROR)> "
    return output

class Stats(object):
    def __init__(self):
        self.headers = []

    def getDict(self):
        return {}

    def getJSON(self):
        import json
        norm_dict = self.getDict()
        json_dict = json.dumps(norm_dict)
        return json_dict


class OS_Stats(Stats):
    def __init__(self):
        self.headers = ["timestamp","os version", "python version", "processor", "memory", "run level", "partitions", "network",
                        "services", "processes", "selinux", "ports"]
        self.timestamp  = time.asctime()
        self.version    = self.getOSVersion()
        self.py_version = self.getPythonVersion()
        self.cpu        = self.getCPUInfo()
        self.memory     = self.getMemoryInfo()
        self.runlevel   = self.getRunLevel()
        self.partitions = self.getPartitionInfo()
        self.network    = self.getNetworkInfo()
        self.services   = self.getServices()
        self.processes  = self.getOSProcessStatus()
        self.selinux    = self.getSELinuxStatus()
        self.ports      = self.getUsedPorts()

    def getDict(self):
        data = [self.timestamp, self.version, self.py_version, self.cpu, self.memory, self.runlevel, self.partitions, self.network,
                self.services, self.processes, self.selinux, self.ports]
        return dict(zip(self.headers,data))

    def prettyPrint(self):
        data_dict = self.getDict()
        print("\n%s - %s\n" % (data_dict["network"]["hostname"].upper().rjust(38), data_dict["network"]["interfaces"][0]))
        # Since dictionaries don't have an "order" each item must be called explicitly in the order we want
        for i in self.headers:
            printData({i : data_dict[i]})

    def getOSVersion(self):
        """
         Description: Get the version of the OS
               Input: None
              Output: OS Version returned as string
        """
        version = os.uname()
        return "%s %s" % (version[0],version[2])

    def getPythonVersion(self):
        """
         Description:
               Input:
              Output:
        """
        version = sys.version_info
        return "%s.%s.%s" % (version[0],version[1],version[2])

    def getCPUInfo(self):
        """
         Description: Gather the CPU information such as type and utilization
               Input: None
              Output: Dictionary containing the following keys:
                      - type
                      - utilization
        """
        type = self.getCPUType()
        utilization = self.getLoadAverage()
        arch = self.getCPUArchitecture()
        cores = self.getLogicalCores()
        headers = ["type","utilization","architecture","logical cores"]
        data = [type,utilization,arch,cores]
        return dict(zip(headers,data))

    def getCPUType(self):
        """
         Description: Get the CPU model name
               Input: None
              Output: CPU model as a string
        """
        output = runOSCommand("`which cat` /proc/cpuinfo | `which grep` \"model name\" | /usr/bin/head -1")
        if "ERROR" in output:
            return output
        cpu_type = output.split(":")[1].strip()
        return cpu_type

    def getLoadAverage(self):
        """
         Description: Get the 1, 5, and 15 minute load averages of the system
               Input: None
              Output: Dictionary containing the following keys:
                      - 1min
                      - 5min
                      - 15min
        """
        dict_headers = ["1min","5min","15min"]
        loadAverages = [("%.2f" % a) for a in os.getloadavg()]
        return dict(zip(dict_headers,loadAverages))

    def getCPUArchitecture(self):
        """
         Description: Get the CPU architecture
               Input: None
              Output: CPU architecture as a string
        """
        output = runOSCommand("`which uname` -p").strip()
        return output

    def getLogicalCores(self):
        """
         Description:
               Input:
              Output:
        """
        output = runOSCommand("`which cat` /proc/cpuinfo | `which grep` processor | `which wc` -l").strip()
        return output

    def getMemoryInfo(self):
        """
         Description: Uses the 'free' utility to find the current memory usage.
               Input: None
              Output: Returns a tuple of the memory used in MB and the percentage of user memory
        """
        output = runOSCommand("`which free` -m")
        if "ERROR" in output:
            return output
        memory_line = output.split("\n")[1].split()
        total_mem = "%s MB" % (memory_line[1])
        mem_used_value = "%s MB" % (memory_line[2])
        mem_free_value = "%s MB" % (memory_line[3])
        mem_used_percent = ("%.2f%s") % (((float(memory_line[2]) / float(memory_line[1])) * 100),"%")
        headers = ["total","used","free","used %"]
        values = [total_mem,mem_used_value,mem_free_value,mem_used_percent]
        return dict(zip(headers,values))

    def getPartitionInfo(self):
        """
         Description: Uses the 'df' tool to find parition info for all partitions
              Input: None
              Output: Output from 'df -h' showing all partitions and utilization
        """
        output = runOSCommand("`which df` -kT")
        if "ERROR" in output:
            return output
        output = output.split("\n")
        regex = "^.*\s+(?P<type>\S+)\s+(?P<size>\S+)\s+(?P<used>\S+)\s+(?P<available>\S+)\s+(?P<used_percent>\S+)\s+(?P<mount>\S+)"
        partitions = {}
        partition_dict = {}
        for i in output:
            if "Filesystem" not in i:
                 match = re.match(regex,i)
                 if match:
                     partition_dict = match.groupdict()
                     mount = partition_dict.pop("mount", None)
                     partitions[mount] = partition_dict
        if output:
            return partitions
        else:
            return "<Unknown>"

    def getNetworkInfo(self):
        """
         Description: Get the hostname and active interfaces on the server
               Input: None
              Output: Dictionary containing the following keys:
                      - hostname
                      - interfaces
        """
        hostname = self.getHostName()
        interfaces = self.getInterfaceInfo()
        dict_headers = ["hostname","interfaces"]
        return dict(zip(dict_headers,[hostname,interfaces]))

    def getHostName(self):
        """
         Description: Get the hostname
               Input: None
              Output: The hostname of the server
        """
        return socket.gethostname()

    def getInterfaceInfo(self):
        """
         Description: Get all of the IPs of active network interfaces using ifconfig
               Input: None
              Output: IP Addresses for all active network interfaces
        """
        output = runOSCommand("`which ifconfig` -a | `which grep` inet | `which grep` -v inet6 | `which grep` -v 127.0.0.1")
        if "ERROR" in output:
            return output
        interface_addr = []
        for i in output.split("\n"):
            if i:
                interface_addr.append(i.split(":")[1].split()[0])
        return interface_addr

    def getServices(self):
        """
         Description: Uses the 'svcs' command to list all of the services available on the server.
               Input: None
              Output: The output from the 'svcs -a' command listing all of the services
        """
        output = runOSCommand("`which chkconfig` --list | `which egrep` \"arc_|syslog|auditd|network|iptables\"")
        if "ERROR" in output:
            return output
        return "\n" + output

    def getOSProcessStatus(self):
        """
         Description:
               Input:
              Output:
        """
        results = []
        services = ["syslog","auditd","rsyslog","iptables"]
        for i in services:
            output = runOSCommand("/etc/init.d/" + i + " status 2> /dev/null")
            if "stopped" in output:
                results.append({i : "STOPPED"})
            elif "running" in output:
                regex = r".*\([^0-9]*([0-9]+)\) is running..."
                matches = re.match(regex,output)
                if matches:
                    results.append({i : "RUNNING (" + matches.group(1) + ")"})
        return results

    def getSELinuxStatus(self):
        """
         Description: Return the SELinux status as a string
               Input: None
              Output: "Permissive", "Enforcing", "Disabled", "N/A"
        """
        output = runOSCommand("getenforce")
        return output

    def getRunLevel(self):
        """
         Description:
               Input:
              Output:
        """
        output = runOSCommand("runlevel").strip()
        if "ERROR" in output:
            return output
        elif "unknown" not in output:
            output = output[-1:]
        else:
            return "<Unknown>"

        try:
            int(output)
            return output
        except ValueError:
            return "<Unknown>"

    def getUsedPorts(self):
        """
         Description: Return a list of open ports and the corresponding process ID/name.
               Input: None
              Output: List of ports and process id/name on same line.
        """
        output = runOSCommand("netstat -nap | grep LISTEN | grep -v STREAM | awk '{ print $4 \" \" $7 }' | cut -d \":\" -f 2 | sort -u")
        if "ERROR" in output:
            return output
        output = output.split("\n")
        port_list = []
        for line in output:
            if line:
                port_info = {}
                line = line.split(" ")
                port_info["port"] = line[0]
                port_info["process"] = line[1]
                port_list.append(port_info)
        return port_list

###########################################
#   END OPERATING SYSTEM INFO FUNCTIONS   #
###########################################

###########################################
#      ARCSIGHT INFORMATION FUNCTIONS     #
###########################################

def getArcSightInfo():
    """
     Description: Locate all connectors on the system and create new Connector objects
           Input: None
          Output: A list of Connector objects representing all of teh connectors on the system
    """
    connectors = []
    directories = runOSCommand("find /opt -wholename *current/user/agent 2> /dev/null")
    for directory in directories.split("\n"):
        if directory:
            path = os.path.normpath(os.path.join(directory,"../.."))
            connectors.append(Connector(path))
    return connectors


class Connector(Stats):
    def __init__(self,path):
        self.headers = ["timestamp", "type", "version", "enabled", "process status", "service", "path", "folder size",
                        "old versions", "destinations", "map files", "categorization files", "log info",
                        "agent.log errors", "wrapper.log errors", "type specifics"]
        self.path           = path
        self.timestamp      = time.asctime()
        self.type           = self.getConnectorType()
        self.version        = self.getConnectorVersion()
        self.enabled        = self.getAgentProperty("agents\[0\]\.enabled")
        self.process_status = self.getProcessStatus()
        self.service        = self.getServiceName()
        self.folder_size    = self.getFolderSize()
        self.old_versions   = self.getOldVersions()
        self.destinations   = self.getDestinations()
        self.map_files      = getFilesInFolder(os.path.join(self.path,"user/agent/map/"),".properties")
        self.cat_files      = getFilesInFolder(os.path.join(self.path,"user/agent/acp/categorizer/current"),".csv")
        self.log_info       = self.getLogInfo()
        self.agent_errors   = self.getLogErrors("agent",10)
        self.wrapper_errors = self.getLogErrors("wrapper",10)
        self.specifics      = self.getTypeSpecifics()

    def getDict(self):
        """
         Description: Return a dict object containing all of the values for the class.  Values must be explicitly
                      included in self.headers and 'data' below
               Input: None
              Output: Dict object representing the Connector instance
        """
        data = [self.timestamp, self.type, self.version, self.enabled, self.process_status, self.service,
                socket.gethostname()+":"+self.path, self.folder_size, self.old_versions, self.destinations,
                self.map_files, self.cat_files, self.log_info, self.agent_errors,self.wrapper_errors, self.specifics]
        zipped_data = dict(zip(self.headers,data))
        return zipped_data

    def prettyPrint(self):
        """
         Description: Recursively print out a dict/list-list-of-dicts structure in a human readable format, indenting
                      for each dictionary level
               Input: None
              Output: Formatted dict printed to stdout
        """
        data_dict = self.getDict()
        # print out values in the same order as they are listed in "self.headers"
        for i in self.headers:
            printData({i : data_dict[i]},1)
        print("")

    def getAgentProperty(self, key):
        """
         Description: Get a specific property value matching a key from the agent.properties file
               Input: key to find in agent.properties
              Output: The value coorsponding to the key
        """
        output = pyGrep(os.path.join(self.path,"user/agent/agent.properties"), key)
        if output:
            regex = r"" + key + "=(?P<value>.*)"
            value = re.match(regex,output).group("value")
            return value
        else:
            return "<Unknown>"

    def getConnectorType(self):
        """
         Description: Grab the connector type from agent.properties
               Input: None
              Output: Connector type as a string (syslog, bsm, auditd, flexmulti_db, etc)
        """
        return self.getAgentProperty("agents\[0\]\.type")
        
    def getConnectorVersion(self):
        """
         Description: Read the connector version from the *common.xml file in the ArcSight Home directrory
               Input: None
              Output: Connector version string (i.e. 5.1.0.1234)
        """
        filename = glob.glob(os.path.join(self.path,"*-common.xml"))
        if not filename:
            return "<Unknown>"
        regex = r".*agents-(?P<version>.*)-common.xml"
        version = re.match(regex,filename[0]).group("version")
        return version
    
    def getProcessStatus(self):
        """
         Description: Return the process status of the connector
               Input: None
              Output: "Running" or "Not running"
        """
        output = runOSCommand("`which ps` -ef | grep %s | grep -v grep" % (self.path))
        if "ERROR" in output:
            return output
        if output:
            return "Running"
        else:
            return "Not running"
            
    def getServiceName(self):
        """
         Description: Find the name of the service that controls the connector
               Input: None
              Output: name of the service script in /etc/init.d/
        """
        fileName = os.path.join(self.path,"user/agent/agent.wrapper.conf")
        output = pyGrep(fileName, "wrapper.ntservice.name=arc_")
        if output:
            regex = r"wrapper.ntservice.name=(?P<name>arc_.*)"
            name_match = re.match(regex,output)
            if name_match:
                name = name_match.group("name")
                return name
            else:
                return "None"
        else:
            return "None"
    
    def getFolderSize(self):
        """
         Description: Find the size of the connector installation folder (i.e. /opt/arcsight/connector1/) in MB
               Input: None
              Output: Folder size in MB
        """
        path = os.path.normpath(os.path.join(self.path, ".."))
        output = runOSCommand("du -m %s | grep %s$" % (path, path))
        if output:
            return output.split()[0]
        else:
            return "<Unknown>"

    def getOldVersions(self):
        """
         Description: Find all of the old versions of the connector caused by upgrades
               Input: None
              Output: List of folders found in <connector root> not including "current"
        """
        folders = []
        for result in os.listdir(os.path.join(self.path, "..")):
            if result != "current":
                folders.append(result)
        if folders:
            return folders
        else:
            return "None"
        
    def getDestinationInfo(self,num,type="",fail_num=0):
        """
         Description: Gather information about a destination based on information in agent.properties (recursive)
               Input: Destination number, Destination Type, Failover number
              Output: Dict containing destination info: agentid, type, host, port, status, receiver
        """
        host_regex = r".*\<Parameter Name\\=\"host\" Value\\=\"(?P<host>[0-9a-zA-Z\.-_]+)\".*"
        port_regex = r".*\<Parameter Name\\=\"port\" Value\\=\"(?P<port>[0-9]+)\".*"
        receiver_regex = r".*\<Parameter Name\\=\"rcvrname\" Value\\=\"(?P<receiver>[0-9a-zA-Z\ \.-_]+)\"/\>\\n.*"

        if type == "failover":
            opt_string = "\.failover\[%s\]" % fail_num
        else:
            opt_string = ""

        dest = {}
        #agents[0].destination[X].agentid OR agents[0].destination[X].failover[Y].agentid
        #agents[0].destination[X].type    OR agents[0].destination[X].failover[Y].type
        #agents[0].destination[X].params  OR agents[0].destination[X].failover[Y].params
        dest["agentid"] = self.getAgentProperty("agents\[0\]\.destination\[%s\]%s\.agentid" % (num,opt_string))
        dest["agentid"] = dest["agentid"].replace("\\","")
        dest["type"] = self.getAgentProperty("agents\[0\]\.destination\[%s\]%s\.type" % (num,opt_string))
        dest["params"] = self.getAgentProperty("agents\[0\]\.destination\[%s\]%s\.params" % (num,opt_string))
        match_host = re.match(host_regex,dest["params"])
        dest_string = ""
        if match_host:
            dest["host"] = match_host.group("host")
            match_port = re.match(port_regex,dest["params"])
            if match_port:
                dest["port"] = match_port.group("port")
                if testConnection(dest["host"],dest["port"]):
                    dest["status"] = "Reachable"
                else:
                    dest["status"] = "Unreachable"
            else:
                dest["port"] = "<Unknown>"
                dest["status"] = "<Unknown>"

            if dest["type"] == "loggersecure":
                dest["receiver"] = re.match(receiver_regex,dest["params"]).group("receiver")
        
        # Remove 'params' from dest dict
        dest.pop("params",None)

        # grab properties from <agentid>.xml
        dest["dns resolution"] = self.getDestinationProperty(dest["agentid"],"Network.HostNameResolutionEnabled")
        dest["batch size"] = self.getDestinationProperty(dest["agentid"],"Batching.BatchSize")
        dest["batch frequency"] = self.getDestinationProperty(dest["agentid"],"Batching.BatchFreq")
        return dest

    def getDestinations(self):
        """
         Description: Get all of the destinations from the agent.properties file
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output: The hostname, port, and receiver (where applicable) for the destination as a dictionary
        """
        count = self.getAgentProperty("agents\[0\]\.destination\.count")
        if count == "<Unknown>":
            return count
        destinations = {}
        for connector_num in xrange(int(count)):
            destination = {}
            failover_count = self.getAgentProperty("agents\[0\]\.destination\[%s\]\.failover\.count" % (connector_num))
            failovers = []
            for failover_num in xrange(int(failover_count)):
                failovers.append(self.getDestinationInfo(connector_num,"failover",failover_num))

            destination["failovers"] = failovers
            destination["primary"] = self.getDestinationInfo(connector_num)
            destinations["Destination " + str(connector_num)] = destination

        if destinations:
            return destinations
        else:
            return "None"

    def getDestinationProperty(self,agentid,key):
        file_name = os.path.join(self.path,"user/agent/%s.xml" % (agentid))
        line = pyGrep(file_name, key)
        if line:
            regex = r".*%s\=\"(?P<value>\S+)\".*" % (key)
            match = re.match(regex,line)
            if match:
                value = match.group("value")
            else:
                value = "<Unknown>"
        else:
            value = "<Unknown>"
        return value


    def getLogInfo(self):
        """
         Description: Gather information from the connector logs
               Input: None
              Output: Dict containing log time frames, status lines, memory info, and garbage collection info
        """
        logs = {}
        logs["time frames"] = self.getLogTimeSpan()
        logs["status"] = self.getLogStatus()
        logs["memory"] = self.getMemoryStatus()
        logs["full gc"] = self.getGCInfo()
        return logs

    def getLogTimeSpan(self):
        """
         Description: Calculate the time difference between the most recent log event and the earliest event still
                      in the main sets of agent log files (agent.log* and agent.out.wrapper.log*)
               Input: None
              Output: Time difference in seconds between oldest and newest log event
        """
        agent_start_time   = self.getTime("agent","first")
        wrapper_start_time = self.getTime("wrapper","first")
        agent_end_time     = self.getTime("agent","last")
        wrapper_end_time   = self.getTime("wrapper","last")

        if agent_end_time and agent_start_time:
            agent_range = agent_end_time - agent_start_time
            agent_range = agent_range.seconds + agent_range.days*86400
        else:
            agent_range = "<Unknown>"

        if wrapper_end_time and wrapper_start_time:
            wrapper_range = wrapper_end_time - wrapper_start_time
            wrapper_range = wrapper_range.seconds + wrapper_range.days*86400
        else:
            wrapper_range = "<Unknown>"

        headers = ["agent.log","wrapper.log"]
        return dict(zip(headers,[agent_range,wrapper_range]))

    def getTime(self,log_type,time_type):
        """
         Description: 
               Input: log_type = "agent" or "wrapper", time_type = "first" or "last"
              Output: 
        """
        def first_time(log_path, log_type):
            max_file = max_file_name(log_path)
            match = None
            try:
                for line in open(max_file):
                    match = re.match(regex[log_type],line)
                    if match:
                        match = match.groupdict()["date"]
                        break
            except IOError:
                return None

            return format_time(match,log_type)

        def last_time(log_path,log_type,lines=5):
            if lines > 50:
                return None

            output = runOSCommand("`which tail` -n %s %s" % (lines, log_path))

            for line in output.split("\n"):
                match = re.match(regex[log_type],line)
                if match:
                    match = match.groupdict()["date"]
                    break
                else:
                    continue

            if match:
                return format_time(match,log_type)
            else:
                last_time(log_path,log_type,lines+5)

        def format_time(time_str,type):
            format = {'agent'   : "%Y-%m-%d %H:%M:%S",
                  'wrapper' : "%Y/%m/%d %H:%M:%S" }
            if not type in format.keys():
                return None
    
            if hasattr(datetime, 'strptime'):
                #python 2.6
                strptime = datetime.strptime
            else:
                #python 2.4 equivalent
                strptime = lambda date_string, format: datetime(*(time.strptime(date_string, format)[0:6]))
    
            the_time = strptime(time_str, format[type])
            return the_time

        def max_file_name(log_path):
            """
             Description: Find the oldest log file based on the log rotation number
                   Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current), file name filter
                  Output: Name of the oldest log file
            """
            nums = []
            files = glob.glob(os.path.join(log_path,".*"))
            nums = [ int(i.split(".")[-1]) for i in files ]
            if nums:
                return log_path + "." + str(max(nums))
            else:
                return log_path

        regex = {'agent'   : r"\[(?P<date>\d\d\d\d-\d\d-\d\d\ \d\d:\d\d:\d\d)\,\d\d\d\].*",
                 'wrapper' : r".*\|.*\| (?P<date>.*) \|.*" }

        file_name = {'agent'   : "agent.log",
                     'wrapper' : "agent.out.wrapper.log" }
                     
        log_path = os.path.join(self.path,"logs")
        log_path = os.path.join(log_path,file_name[log_type])

        functions = {'first' : first_time(log_path,log_type),
                     'last'  : last_time(log_path,log_type) }

        return functions[time_type]

    def getLogStatus(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        output = runOSCommand("`which grep` \"\[INFO \]\" %s | grep \"ET=\" | tail -n 1" % (os.path.join(self.path,"logs/agent.out.wrapper.log")))
        if "ERROR" in output:
            return output
        if output:
            regex = r".*\{C=(?P<cache>[0-9]+), ET=(?P<ET>Up|Down), HT=(?P<HT>Up|Down), N=(?P<name>[0-9A-Za-z\-\_ ]+), S=(?P<Events>[0-9]+), T=(?P<eps>[0-9\.]+)\}"
            match = re.match(regex,output)
            if match:
                return match.groupdict()
            else:
                return "None"
        else:
            return "None"

    def getMemoryStatus(self):
        """
         Description: Get latest memory information from connector logs
               Input: None
              Output: Dict containing the "used" memory and the "allocated" memory, in KB
        """
        #[GC 275856K->206027K(290176K), 0.0230360 secs]
        file_name = os.path.join(self.path,"logs/agent.out.wrapper.log")
        output = runOSCommand("`which grep` \"\[GC \" %s | tail -n 1" % (file_name))
        regex = r'.*\[GC \d+K->(?P<used>\d+K)\((?P<allocated>\d+K)\), \d+\.\d+ secs\]'
        match = re.match(regex,output)
        if match:
            return match.groupdict()
        else:
            return "None"

    def getGCInfo(self):
        """
         Description: Find the latest Garbage Collection status
               Input: None
              Output: Dict containing GC info
        """
        gc = {}
        gc["last gc"] = self.getLengthOfLastGC()
#        gc["time between gcs"] = self.getTimeBetweenGCs()
        return gc

    def getLengthOfLastGC(self):
        """
         Description: Pull memory usage data from the latest Full GC event in the logs
               Input: None
              Output: Dict containing the "start" memory usage, "end" memory usage, and "time" taken
        """
        file_name = os.path.join(self.path,"logs/agent.out.wrapper.log")
        output = runOSCommand("`which grep` \"Full GC\" -A1 %s | `which grep` secs | tail -n 1" % (file_name))
        regex = r'.* (?P<start>\d+K)->(?P<end>\d+K)\(\d+K\), (?P<time>\d+\.\d+) secs\]'
        match = re.match(regex,output)
        if match:
            return match.groupdict()
        else:
            return "None"

    

    def getLogErrors(self, type, number):
        """
         Description: Get errors from ArcSight connector logs
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current), type = "agent" or "wrapper"
              Output: List of errors
        """
        if type == "agent":
            path = os.path.join(self.path, "logs/agent.log")
        elif type == "wrapper":
            path = os.path.join(self.path, "logs/agent.out.wrapper.log")
        else:
            return "None"
        output = runOSCommand("`which grep` ERROR %s | tail -n %s" % (path, number))
        output = output.split("\n")
        error_list = []
        for i in output:
            i = i[0:140]    # Grab first 140 characters of the error message
            if i:
                error_list.append(i)
        if error_list:
            return error_list
        else:
            return "None"
            
    def getTypeSpecifics(self):
        """
         Description: Return specific values based on what self.type is.
               Input: None
              Output: Dict object with varying structure
        """
        if self.type == 'windowsfg':
            return self.getTypeSpecifics_Windows()
        else:
            return "None"

    def getTypeSpecifics_Windows(self):
        """
         Description: Find parameters specific to Windows connectors.  Hostname
               Input: 
              Output: 
        """
        hosts = {}
        host_count = self.getAgentProperty("agents\[0\].windowshoststable.count")
        try:
            host_count = int(host_count)
        except ValueError:
            return "<Unknown>"
        for i in xrange(host_count):
            hostname = self.getAgentProperty("agents\[0\].windowshoststable\[%d\].hostname" % (i))
            hosts[hostname] = {}
            for property in ["windowsversion","application","security","system"]:
                hosts[hostname][property] = self.getAgentProperty("agents\[0\].windowshoststable\[%d\].%s" % (i,property))
        return hosts

###########################################
#    END ARCSIGHT INFORMATION FUNCTIONS   #
###########################################
def pyGrep(file, pattern):
    """
     Description: Search through a file for a given pattern, return first match
           Input: File name, pattern to search
          Output: First matched line from the file
    """
    try:
        lines = open(file,"rb")
    except IOError:
        return None
    else:
        regex = re.compile(pattern)
        for line in lines:
            if regex.search(line):
                return line.strip()
        else:
            return None


def getFilesInFolder(file_path,filter="*"):
    """
     Description: Get a list of all of the files in a directory matching a given filter
           Input: Path to directory, file filter
          Output: A list of all file names in the given directory
    """
    headers = ["size","creation time","md5","default"]
    default_md5s = ["1625152a3909d9c5fe1d7b91b9cd6048","cd8be946ff99c91480f8fad121c9ada6"]
    files = {}
    for walk_result in os.walk(file_path):
        for file_name in walk_result[-1]:
            if filter in file_name:
                current_file = os.path.join(walk_result[0],file_name)
                current_file_stats = os.stat(current_file)
                size = current_file_stats.st_size
                ctime = time.asctime(time.localtime(current_file_stats.st_ctime))
                md5 = md5_checksum(current_file)
                if md5 in default_md5s:
                    default = "True"
                else:
                    default = "False"
                file_data = [size,ctime,md5,default]
                files[file_name] = (dict(zip(headers,file_data)))
    if files:
        return files
    else:
        return None


def testConnection(target, port):
    """
     Description: Attempt to connect to a given hostname+port
           Input: target - address/hostname to ping
          Output: True if connection is successful, False otherwise
    """
#    return False
    s = socket.socket()
    try:
        s.connect((target,int(port)))
        s.close()
        return True
    except Exception, e:
        s.close()
        return False


def doNsLookup(target):
    """
     Description: Get the hostname of the current system
           Input: The IP address of the target
          Output: THe hostname of the target, or "Cannot resolve
    """
    try:
        return socket.gethostbyname(target)
    except:
        return "Cannot resolve %s" % (target)

def printHeader(header):
    width = 80
    print("#"*width)
    print("#%s#" % (header.center(width-2)))
    print("#"*width)

def printData(data, indent=0):
    """
     Description: Print data using indent tabs based on depth of list and dictionaries
           Input: A dictionary of data, the starting indent (optional)
          Output: Formatted data printed to stdout
    """
    spacing = "    "
    for key,value in data.iteritems():
        if isinstance(value,dict):
            print("%s%s:" % (spacing*indent,key.upper()))
            printData(value,indent+1)
        elif isinstance(value,list):
            if len(value) == 1 and isinstance(value[0],str):
                print("%s%s: %s" % (spacing*indent,key.upper(),value[0]))
            else:
                print("%s%s:" % (spacing*indent,key.upper()))
                for i in value:
                    if isinstance(i,dict):
                        printData(i,indent+1)
                    else:
                        print("%s%s" % (spacing*(indent+1),str(i)))

        else:
            print("%s%s: %s" % ("    "*indent,key.upper(),value))


def sendJSON(host, index, message):
    """    the_date = time.strftime('%Y-%m-%d',time.localtime())
    url = "/stats-%s/%s/" % (the_date,index)
    conn = httplib.HTTPConnection(host,9200)
    conn.request("POST",url,message)
    response =  conn.getresponse()
    if response.status in [200,201]:
        print "Successfully sent data to %s" % (host)
        print response.read()
    else:
        print "ERROR sending data: %s %s" % (response.status, response.reason)
    """
    print message


def md5_checksum(file_name):
    """
     Description: Calculate the MD5 hash value of a given file using different methods
                  depending on the OS and Python version.
           Input: The path to the file.
          Output: The MD5 hash of the file.
    """
    try:
        open(file_name,"r")
    except:
        return "<Unknown>"

    if sys.version_info > (2,5):  # hashlib not supported in Python 2.5 or lower
        import hashlib
        use_md5_hash = hashlib.md5()

        try:
            use_md5_hash.update(open(file_name).read())
        except Exception,exception_output:
            print exception_output
            return "<Unknown>"
        else:
            return use_md5_hash.hexdigest().strip()

    else:
        output = runOSCommand("`which md5sum` " + file_name + " | cut -d \" \" -f 1")
        return output.strip()


def printHelp():
    print("Usage: python gather.py [print] [json] [cef] [syslog] [<hostname>] [<port>]")
    print("")
    print("Script must be run as the root user.")
    print("Usage Examples:")
    print("  - Print information in human-readable format:")
    print("      python gather.py print")
    print("  - Sending JSON to another host via syslog:")
    print("      python gather.py json syslog myserver.local 5514")
    print("  - Send JSON data to another host and also print human readable data:")
    print("      python gather.py json print syslog myserver.local 5514")


def main():
    PRINT = False
    JSON = False
    SYSLOG = False
    CEF = False
    HOST = ""

    if os.geteuid() != 0:
        print("ERROR: Script must be run by root. Exiting.")
        sys.exit(1)
    if 'linux' not in sys.platform:
        print("ERROR: Attempting to run on an unsupported platform, exiting.")
        sys.exit(2)

    for i in sys.argv:
        if i == 'help' or i == 'h' or i == '-h':
            printHelp()
            sys.exit(0)
        elif i == 'print':
            PRINT = True
        elif i == 'json':
            JSON = True
        elif i == 'cef':
            CEF = True
        elif i.isalnum():
            SYSLOG = True
            PORT = int(i)
        elif i:
            HOST = i
    
    osData = OS_Stats()
    if PRINT:
        printHeader("SERVER INFORMATION")
        osData.prettyPrint()
        printHeader("ARCSIGHT INFORMATION")

    if JSON:
        sendJSON(HOST,"server",osData.getJSON())

    connectorList = getArcSightInfo()
    if connectorList:
        for index,connector in enumerate(connectorList):
            if PRINT:
                print("Connector " + str(index+1) + ": ")
                connector.prettyPrint()
            if JSON:
                sendJSON(HOST,"connector",connector.getJSON())
    else:
        if PRINT:
            print("")
            print("No ArcSight connector services appear to be installed on this system.")
            print("")

if __name__ == '__main__':
    main()
