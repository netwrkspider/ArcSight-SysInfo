#!/usr/bin/python
"""
Gathers system information useful for diagnosing issues related to OS tier and
ArcSight connector level issues.

__author__ = "Adam Reber"
__email__ = "adam.reber@gmail.com"
__version__ = "0.5"
__date__ = "05/09/2013"
__status__ = "Development"


History:
    0.1 (09/13/2012)
    0.2 (09/19/2012) - Added native grep-like function
    0.3 (10/16/2012) - Changed how connectors are detected, should now find all arcsight
                       connectors under, even if they are not installed as a service.
    0.4 (02/05/2013) - Modified to use class structure rather than dictionaries
    0.5 (05/09/2013) - Added connector-type specific attributes

Future:
    - Support for multiple output formats (XML,CSV,JSON,etc)
"""

import os,sys,string,httplib,subprocess,re,time,glob,socket,logging
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

class OS_Stats(object):
    def __init__(self):
        self.version = self.getOSVersion()
        self.py_version = self.getPythonVersion()
        self.cpu = self.getCPUInfo()
        self.memory = self.getMemoryInfo()
        self.partitions = self.getPartitionInfo()
        self.network = self.getNetworkInfo()
        self.runlevel = self.getRunLevel()
        self.services = self.getServices()
        self.processes = self.getOSProcessStatus()
        self.selinux = self.getSELinuxStatus()
        self.ports = self.getUsedPorts()

    def prettyPrint(self):
        headers = ["os version","python version","processor","memory","run level","partitions",
                   "network","services","processes","selinux","ports"]
        data = [self.version,self.py_version,self.cpu,self.memory,self.runlevel,self.partitions,
                self.network,self.services,self.processes,self.selinux,self.ports]

        zipped_data = dict(zip(headers,data))

        print("\n%s - %s\n" % (zipped_data["network"]["hostname"].upper().rjust(38), zipped_data["network"]["interfaces"][0]))
        # Since dictionaries don't have an "order" each item must be called explicitly in the order we want
        for i in headers:
            printData({i : zipped_data[i]})

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
        if 'linux' in sys.platform:
            output = runOSCommand("`which cat` /proc/cpuinfo | `which grep` \"model name\" | /usr/bin/head -1")
            if "ERROR" in output:
                return output
            cpu_type = output.split(":")[1].strip()
            return cpu_type
        elif 'sunos' in sys.platform:
            return "<Unknown>"
        else:
            return "<Unknown>"

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
         Description: Uses the 'memstat' and 'mdb' or 'free' OS tools to find the current memory usage.
               Input: None
              Output: Returns a tuple of the memory used in MB and the percentage of user memory
        """
        if 'sunos' in sys.platform:
            output = runOSCommand("echo ::memstat|mdb -k|grep \"Free (freelist)\"")
            if "ERROR" in output:
                return output
            output = output.split()
            mem_used_value = "%s MB" % (output[-2])
            mem_used_percent = output[-1]
        elif 'linux' in sys.platform:
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
        else:
            headers = ["total","used","free","used %"]
            values = ["<Unknown>","<Unknown>","<Unknown>","<Unknown>"]
        return dict(zip(headers,values))

    def getPartitionInfo(self):
        """
         Description: Uses the 'df' tool to find parition info for all partitions
              Input: None
              Output: Output from 'df -h' showing all partitions and utilization
        """
        output = runOSCommand("`which df` -h")
        if "ERROR" in output:
            return output
        output = "\n" + output
        if output:
            return output
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
        if 'sunos' in sys.platform:
            interface_addr = output.split()[1]
        elif 'linux' in sys.platform:
            interface_addr = []
            for i in output.split("\n"):
                if i:
                    interface_addr.append(i.split(":")[1].split()[0])
    #        interface_addr = output.split()[1].split(":")[1]
        return interface_addr

    def getServices(self):
        """
         Description: Uses the 'svcs' command to list all of the services available on the server.
               Input: None
              Output: The output from the 'svcs -a' command listing all of the services
        """
        if 'sunos' in sys.platform:
            output = "\n" + runOSCommand("svcs -a")
            if "ERROR" in output:
                return output
        elif 'linux' in sys.platform:
            output = runOSCommand("`which chkconfig` --list | `which egrep` \"arc_|syslog|auditd|network|iptables\"")
            if "ERROR" in output:
                return output
        else:
            return "<Unknown>"
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
                results.append(i + ": STOPPED")
            elif "running" in output:
                regex = r".*\([^0-9]*([0-9]+)\) is running..."
                matches = re.match(regex,output)
                if matches:
                    results.append(i + ": RUNNING (" + matches.group(1) + ")")
        return results

    def getSELinuxStatus(self):
        """
         Description: Return the SELinux status as a string
               Input: None
              Output: "Permissive", "Enforcing", "Disabled", "N/A"
        """
        if 'linux' in sys.platform:
            output = runOSCommand("getenforce")
            return output
        else:
            return "N/A"

    def getRunLevel(self):
        """
         Description:
               Input:
              Output:
        """
        if 'sunos' in sys.platform:
            output = runOSCommand("user -r")
            if "ERROR" in output:
                return output
            output = output[18:21]
            output = output.strip()
        elif 'linux' in sys.platform:
            output = runOSCommand("runlevel").strip()
            if "ERROR" in output:
                return output
            elif "unknown" not in output:
                output = output[-1:]
            else:
                return "<Unknown>"
        else:
            return "<Unknown>"
        try:
            int(output)
            return output
        except ValueError:
            return "<Unknown>"

    def getUsedPorts(self):
        """
         Description: Return a list of open ports and the corresponding process ID/name.  On solaris
                      only ports 9001-9020 are checked.
               Input: None
              Output: List of ports and process id/name on same line.
        """
        if 'linux' in sys.platform:
            output = runOSCommand("netstat -nap | grep LISTEN | grep -v STREAM | awk '{ print $4 \" \" $7 }' | cut -d \":\" -f 2 | sort -u")
            if "ERROR" in output:
                return output
            output = output.split("\n")
            port_list = ["  PORT  PROCESS"]
            for line in output:
                if line:
                    line = line.split(" ")
                    port_str = "%6s  %s" % (line[0],line[1])
                    port_list.append(port_str)
            return port_list

        elif 'sunos' in sys.platform:
            return "<Unknown>"
        else:
            return "<Unknown>"


###########################################
#   END OPERATING SYSTEM INFO FUNCTIONS   #
###########################################

###########################################
#      ARCSIGHT INFORMATION FUNCTIONS     #
###########################################

def getArcSightInfo():
    """
     Description:
           Input: None
          Output:
    """
    connectors = []
    directories = runOSCommand("find / -wholename *current/user/agent 2> /dev/null")
    for directory in directories.split("\n"):
        if directory:
            path = os.path.normpath(os.path.join(directory,"../.."))
            connectors.append(Connector(path))
    return connectors

class Connector(object):
    def __init__(self,path):
        self.path           = path
        self.folder_size    = self.getFolderSize()
        self.service        = self.getServiceName()
        self.version        = self.getConnectorVersion()
        self.type           = self.getConnectorType()
        self.specifics      = self.getTypeSpecifics()
        self.destinations   = self.getDestinations()
        self.enabled        = self.getAgentProperty("agents\[0\]\.enabled")
        self.cat_files      = getFilesInFolder(os.path.join(self.path,"user/agent/acp/categorizer/current"),".csv")
        self.map_files      = getFilesInFolder(os.path.join(self.path,"user/agent/map/"),".properties")
        self.old_versions   = self.getOldVersions()
        self.log_info       = self.getLogInfo()
        self.process_status = self.getProcessStatus()
        self.agent_errors   = self.getLogErrors("agent")
        self.wrapper_errors = self.getLogErrors("wrapper")

    def prettyPrint(self):
        _headers = ["type","version","enabled","process status","service","path","folder size","old versions","destinations","map files","categorization files","log info","agent.log errors","wrapper.log errors","type specifics"]
        _data = [self.type,self.version,self.enabled,self.process_status,self.service,self.path,self.folder_size,self.old_versions,self.destinations,self.map_files,self.cat_files,self.log_info,self.agent_errors,self.wrapper_errors,self.specifics]
        _zipped_data = dict(zip(_headers,_data))
        for i in _headers:
            printData({i : _zipped_data[i]},1)
        print("")

    def getFolderSize(self):
        path = os.path.normpath(os.path.join(self.path, ".."))
        output = runOSCommand("du -h %s | grep %s$" % (path, path))
        if output:
            return output.split()[0]
        else:
            return "<Unknown>"

    def getConnectorVersion(self):
        """
         Description: Read the connector version from the *common.xml file in the ArcSight Home directrory
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output: Connector version string (i.e. 5.1.0.1234)
        """
        _filename = glob.glob(os.path.join(self.path,"*-common.xml"))
        if not _filename:
            return "<Unknown>"
        _regex = r".*agents-(?P<version>.*)-common.xml"
        _version = re.match(_regex,_filename[0]).group("version")
        return _version

    def getConnectorType(self):
        """
         Description: Grab the connector type from agent.properties
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output: Connector type as a string (syslog, bsm, auditd, flexmulti_db, etc)
        """
        return self.getAgentProperty("agents\[0\]\.type")

    def getTypeSpecifics(self):
        """
         Description:
               Input:
              Output:
        """
        if self.type == 'windowsfg':
            return self.getTypeSpecifics_Windows()
        else:
            return "None"

    def getTypeSpecifics_Windows(self):
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

    def getDestinations(self):
        """
         Description: Get all of the destinations from the agent.properties file
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output: The hostname, port, and receiver (where applicable) for the destination as a dictionary
        """
        _count = self.getAgentProperty("agents\[0\]\.destination\.count")
        if _count == "<Unknown>":
            return _count
        _destinations = []
        for i in xrange(int(_count)):
            _type = self.getAgentProperty("agents\[0\]\.destination\["+str(i)+"\]\.type")
            _params = self.getAgentProperty("agents\[0\]\.destination\["+str(i)+"\]\.params")
            _host_regex = r".*\<Parameter Name\\=\"host\" Value\\=\"(?P<host>[0-9a-zA-Z\.-_]+)\".*"
            _port_regex = r".*\<Parameter Name\\=\"port\" Value\\=\"(?P<port>[0-9]+)\".*"
            _match_host = re.match(_host_regex,_params)
            if _match_host:
                _host = _match_host.group("host")
                _match_port = re.match(_port_regex,_params)
                if _match_port:
                    _port = _match_port.group("port")
                    if testConnection(_host,_port):
                        _connect_test = "Reachable"
                    else:
                        _connect_test = "Unreachable"
                else:
                    _port = "<Unknown>"
                    _connect_test = "<Unknown>"

                if _type == "loggersecure":
                    _receiver_regex = r".*\<Parameter Name\\=\"rcvrname\" Value\\=\"(?P<receiver>[0-9a-zA-Z\ \.-_]+)\"/\>\\n.*"
                    _receiver = re.match(_receiver_regex,_params).group("receiver")
                    _destination = "%12s - %30s:%s %s" % (_connect_test, _host, _port, _receiver)
                else:
                    _destination = "%12s - %30s:%s " % (_connect_test, _host, _port)
                _destinations.append(_destination)
            if _destinations:
                return _destinations
            else:
                return "None"

    def getAgentProperty(self, key):
        """
         Description: Get a specific property value matching a key from the agent.properties file
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current), key to find in agent.properties
              Output: The value coorsponding to the key
        """
        output = pyGrep(os.path.join(self.path,"user/agent/agent.properties"), key)
        if output:
            regex = r"" + key + "=(?P<value>.*)"
            value = re.match(regex,output).group("value")
            return value
        else:
            return "<Unknown>"

    def getServiceName(self):
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


    def getAgentConfig(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        pass

    def getParserInfo(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        pass

    def getOldVersions(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        folders = []
        for result in os.listdir(os.path.join(self.path, "..")):
            if result != "current":
                folders.append(result)
        if folders:
            return folders
        else:
            return "None"

    def getServiceStatus(self,service):
        """
         Description:
               Input:
              Output:
        """
        output = runOSCommand("/etc/init.d/" + service + " status")
        if output:
            return output
        else:
            return "<Unknown>"
        pass

    def getProcessStatus(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        output = runOSCommand("`which ps` -ef | grep %s | grep -v grep" % (self.path))
        if "ERROR" in output:
            return output
        if output:
            return "Running"
        else:
            return "Not running"

    def getLogInfo(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        logs = {}
        logs["time frames"] = self.getLogTimeSpan()
        logs["status"] = self.getLogStatus()
        logs["memory"] = self.getMemoryStatus()
        logs["full gc"] = self.getGCInfo()
        return logs

    def getGCInfo(self):
        gc = {}
        gc["last gc"] = self.getLengthOfLastGC()
#        gc["time between gcs"] = self.getTimeBetweenGCs()
        return gc

    def getLengthOfLastGC(self):
        file_name = os.path.join(self.path,"logs/agent.out.wrapper.log")
        output = runOSCommand("`which grep` \"Full GC\" -A1 %s | `which grep` secs | tail -n 1" % (file_name))
        regex = r'.* (?P<start>\d+K)->(?P<end>\d+K)\(\d+K\), (?P<time>\d+\.\d+) secs\]'
        match = re.match(regex,output)
        if match:
            return match.groupdict()
        else:
            return "None"


    def getMemoryStatus(self):
        #[GC 275856K->206027K(290176K), 0.0230360 secs]
        file_name = os.path.join(self.path,"logs/agent.out.wrapper.log")
        output = runOSCommand("`which grep` \"\[GC \" %s | tail -n 1" % (file_name))
        regex = r'.*\[GC \d+K->(?P<used>\d+K)\((?P<allocated>\d+K)\), \d+\.\d+ secs\]'
        match = re.match(regex,output)
        if match:
            return match.groupdict()
        else:
            return "None"


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

    def getLogTimeSpan(self):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
              Output:
        """
        if sys.version_info < (2,5):
            return "<Unknown> (Incompatible version of Python)"

        agent_start_time   = self.getFirstTime("agent")
        wrapper_start_time = self.getFirstTime("wrapper")
        agent_end_time     = self.getLastTime("agent")
        wrapper_end_time   = self.getLastTime("wrapper")
        if agent_end_time and agent_start_time:
            agent_range = agent_end_time - agent_start_time
        else:
            agent_range = "<Unknown>"

        if wrapper_end_time and wrapper_start_time:
            wrapper_range = wrapper_end_time - wrapper_start_time
        else:
            wrapper_range = "<Unknown>"

        headers = ["agent.log","wrapper.log"]
        return dict(zip(headers,[agent_range,wrapper_range]))

    def getFirstTime(self, log_type):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current), type = "agent" or "wrapper"
              Output:
        """
        file_path = os.path.join(self.path,"logs")
        if "agent" in log_type:
            max_file = self.getMaxFileName(file_path,"agent.log.*")
            regex = r"\[(?P<date>\d\d\d\d-\d\d-\d\d\ \d\d:\d\d:\d\d)\,\d\d\d\].*"

        elif "wrapper" in log_type:
            max_file = self.getMaxFileName(file_path,"agent.out.wrapper.log.*")
            regex = r".*\|.*\| (?P<date>.*) \|.*"
        log_path = os.path.join(file_path,max_file)
        match = None
        try:
            for line in open(log_path):
                match = re.match(regex,line)
                if match:
                    match = match.groupdict()["date"]
                    break
        except IOError:
            return None

        if match:
            the_time = None
            if "agent" in log_type:
                the_time = datetime.strptime(match, "%Y-%m-%d %H:%M:%S")
            elif "wrapper" in log_type:
                the_time = datetime.strptime(match, "%Y/%m/%d %H:%M:%S")
            return the_time
        else:
            return None

    def getLastTime(self,log_type,lines=5):
        """
         Description:
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current)
                      type = "agent" or "wrapper", number of lines to return
              Output:
        """
        if lines > 50:
            return None

        log_path = os.path.join(self.path,"logs")
        if log_type == "agent":
            log_path = os.path.join(log_path,"agent.log")
            regex = r"\[(?P<date>\d\d\d\d-\d\d-\d\d\ \d\d:\d\d:\d\d)\,\d\d\d\].*"

        elif log_type == "wrapper":
            log_path = os.path.join(log_path,"agent.out.wrapper.log")
            regex = r".*\|.*\| (?P<date>.*) \|.*"
        else:
            return None

        output = runOSCommand("`which tail` -n %s %s" % (lines, log_path))

        for line in output.split("\n"):
            match = re.match(regex,line)
            if match:
                match = match.groupdict()["date"]
                break
            else:
                continue

        if match:
            the_time = None
            if "agent" in log_type:
                the_time = datetime.strptime(match, "%Y-%m-%d %H:%M:%S")
            elif "wrapper" in log_type:
                the_time = datetime.strptime(match, "%Y/%m/%d %H:%M:%S")
            return the_time
        else:
            self.getLastTime(self.path,lines+5)

    def getMaxFileName(self, log_path, file_filter):
        """
         Description: Find the oldest log file based on the log rotation number
               Input: Path to connector home (i.e. /opt/app/arcsight/syslog/current), file name filter
              Output: Name of the oldest log file
        """
        nums = []
        files = glob.glob(os.path.join(self.path,file_filter))
        nums = [ int(i.split(".")[-1]) for i in files ]
        if nums:
            return string.replace(filter,"*",str(max(nums)))
        else:
            return file_filter[:-2]

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


def getFilesInFolder(file_path,filter="*"):
    """
     Description: Get a list of all of the files in a directory matching a given filter
           Input: Path to directory, file filter
          Output: A list of all file names in the given directory
    """
    default_md5s = ["1625152a3909d9c5fe1d7b91b9cd6048","cd8be946ff99c91480f8fad121c9ada6"]
    files = []
    for walk_result in os.walk(file_path):
        for file in walk_result[-1]:
            if filter in file:
                current_file = os.path.join(walk_result[0],file)
                current_file_stats = os.stat(current_file)
                size = current_file_stats.st_size
                ctime = time.asctime(time.localtime(current_file_stats.st_ctime))
                md5 = md5_checksum(current_file)
                if md5 in default_md5s:
                    default = "(Default)"
                else:
                    default = ""
                file_info = "%20s  %7s bytes  %s  %s %s" % (file,size,ctime,md5,default)
                files.append(file_info)
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
    s = socket.socket()
    try:
        s.connect((target,int(port)))
        s.close()
        return True
    except Exception, e:
        s.close()
        return False
#    timeout = socket.setdefaulttimeout(15)
#    try:
#        c = httplib.HTTPSConnection(target, port)
#        c.request("GET", "/")
#        response = c.getresponse()
#        if "200" or "302" in str(response.status) and "OK" in response.reason:
#            return True
#        else:
#            return False
#    except:
#        return False
#    return False

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
    for key,value in data.iteritems():
        if isinstance(value,dict):
            print("%s%s:" % ("    "*indent,key.upper()))
            printData(value,indent+1)
        elif isinstance(value,list):
            if len(value) == 1:
                print("%s%s: %s" % ("    "*indent,key.upper(),value[0]))
            else:
                print("%s%s:" % ("    "*indent,key.upper()))
                for i in value:
                    if isinstance(i,dict):
                        print("%s%s: " % ("    "*indent,key.upper()))
                        printData(i,indent+1)
                    else:
                        print("%s%s" % ("    "*(indent+1),str(i)))

        else:
            print("%s%s: %s" % ("    "*indent,key.upper(),value))

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
        if 'linux' in sys.platform:
            output = runOSCommand("`which md5sum` " + file_name + " | cut -d \" \" -f 1")
        elif 'sunos' in sys.platform:
            output = runOSCommand("digest -a md5 " + file_name)
        else:
            return "<Unknown>"
        return output.strip()

def main():
    if os.geteuid() != 0:
        print("ERROR: Script must be run by root. Exiting.")
        sys.exit(1)
    if 'linux' not in sys.platform and 'sunos' not in sys.platform:
        print("ERROR: Attempting to run on an unsupported platform, exiting.")
        sys.exit(2)

    printHeader("SERVER INFORMATION")
    osData = OS_Stats()
    osData.prettyPrint()

    printHeader("ARCSIGHT INFORMATION")
    connectorList = getArcSightInfo()
    if connectorList:
        for index,connector in enumerate(connectorList):
            print("Connector " + str(index+1) + ": ")
            connector.prettyPrint()
    else:
        print("")
        print("No ArcSight connector services appear to be installed on this system.")
        print("")

if __name__ == '__main__':
    main()
