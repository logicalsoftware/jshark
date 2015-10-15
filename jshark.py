#!/usr/bin/env python

"""Generate formatted output of pkt (etherpeek) files.

-PRIMARY
- take in a directory or file
- recurse for list of files if dir given
- run tshark on all pkt files
- output to file.psv for pipe delimited file
- have options for standard parsing: "http detail", "http standard", "smtp standard", "smtp detail"
- always give frame.time, ip.src, eth.src, ip.dst, eth.dst, unless overriden by options.

- SECONDARY
- provide config file that can describe other output types
e.g:  http detail = frame.protocols http.referer http.request.uri http.user_agent
      http simple = http.referer http.user_agent

- TODO:
    - Add display filter for -R option to conf file
    - filter for only relevant data
    - default to ignore broadcasts
    - get list of tshark return codes for better error output
    - have script create a new directory for each run
    - pull session data for each run (tcpflow?)
"""

__author__ = "Jason Sherman"
__version__ = "$Revision: .1 $"
__date__ = "$Date: 2011/02/20 19:46:00 $"

import os
import sys
import time
import fnmatch
import logging
import tempfile
import subprocess
import ConfigParser

from optparse import OptionParser

"""GLOBALS
"""
#----------------------------------------------------------------------
FIELD_SECTION = "fields"
GREP_SECTION = "greps"
DISPLAY_FILTER_SECTION = "filters"
options=None
config=None
args = None
start_time = None
mem = None

"""CLASSES
"""
########################################################################
class Process:
    """Processes a pkt file
    """

    #----------------------------------------------------------------------
    def __init__(self):
        """Constructor"""


"""FUNCTIONS
"""
#----------------------------------------------------------------------
def __sanitycheck(condition, parser, msg):
    """log error message if condition met, then exit
    """
    if (condition):
        logger.error(msg)
        usage(parser)
        sys.exit(2)


#----------------------------------------------------------------------
def __parsecl():
    """build the parser object and process the command line
    """
    global start_time
    global options
    global args
    global mem

    parser.add_option("-e", "--extension", dest="extension", default="pkt", help="input file extension", metavar="EXT")
    parser.add_option("-R", "--read_filter", dest="filters", default="http_detail", help="set the read filter as defined in the config file")
    parser.add_option("-T", "--display_fields", dest="fields", default="http_detail", help="set the display fields based on config file settings")
    parser.add_option("-i", "--inpath", dest="inpath", help="input file path", metavar="FILEORDIR")
    parser.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="log debug output")
    parser.add_option("-m", "--maxprocs", dest="maxprocs", default=4, type="int", help="max number of processes to spawn at one time")
    parser.add_option("-o", "--outpath", dest="outpath", help="output file path", metavar="FILEORDIR")
    parser.add_option("-r", "--recurse", dest="recurse", default=False, action="store_true", help="recurse into inpath to find more files", metavar="PARSE")
    parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true", help="extra info on stdout")

    (options, args) = parser.parse_args()

    ## mandatory options need to have a sanity check
    __sanitycheck((options.inpath == None), parser, "Error: input path or file not provided")

    if options.outpath == None:
        if os.path.isdir(options.inpath):
            outdir = options.inpath
        else:
            outdir = os.path.dirname(options.inpath)
    else:
        outdir = options.outpath

    outpath = os.path.join(outdir, "%s_%s" % (options.filters.replace(" ", "-"), start_time))

    try:
        os.mkdir(outpath)
        options.outpath = outpath
    except OSError:
        logger.info('Output directory already exists - %s' % outpath)

    if options.debug == True:
        logger.setLevel(logging.DEBUG)

    # calculate the maximum number of processes to run, up to
    # 75% of available RAM based on ~1GB files
    try:
        mem = subprocess.Popen(["free", "-m"], stdout=subprocess.PIPE)# -m | grep buffers/cache")
        o = mem.communicate()
        o = o[0].split('\n')[2].split()[-1]
        o = int(o)/1333
        if o < options.maxprocs:
            options.maxprocs = o
    except:
        pass



#----------------------------------------------------------------------
def __parsecfg():
    """parses jshark.conf
    """
    global config
    config = ConfigParser.RawConfigParser()
    config.read('jshark.conf')


#----------------------------------------------------------------------
def __openfile(file, access):
    """open a file and return its handle
    """
    try:
        handle = open(file, access)
    except IOError, error:
        logger.error("I/O error - %s" % error)
        sys.exit(2)

    return handle


#----------------------------------------------------------------------
def __getfiles(path, pattern):
    """identifiy file or recurse into a directory to get a full list of
    files based on the given extension
    """
    global options

    allfiles = []

    if(os.path.isfile(path)):
        allfiles.append(path)

    elif(options.recurse):
        for root, dirs, files in os.walk(path):
            for basename in files:
                if fnmatch.fnmatch(basename, pattern):
                    filename = os.path.join(root, basename)
                    allfiles.append(filename)
    else:
        #for root, dirs, files in os.listdir(path):
        root = os.path.realpath(path)
        files = os.listdir(path)
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                allfiles.append(filename)

    for files in allfiles:
        yield files


#----------------------------------------------------------------------
def __buildtshark():
    """build the tshark command line using options from jshark.conf
    """
    global options
    global config

    display_options = ""
    display_fields = ""
    display_filters = ""
    fields = ""

    # The 'all' section gets added so some basic info is always present
    field_option = options.fields
    if 'all' not in field_option:
        field_option = 'all ' + field_option

    for fo in field_option.split():
        fields = "%s %s" % (fields, config.get(FIELD_SECTION, fo))

    fields = fields.split()
    for f in fields:
        display_fields += "-e %s " % f


    filter_option = options.filters
    if len(filter_option) > 1:
        display_filters = filter_option.split()[0]
        for fo in filter_option.split()[1:]:
            display_filters += " && %s" % (config.get(DISPLAY_FILTER_SECTION, fo))

    cmdline = 'tshark -n -R "%s" -T fields %s -E header=y -E separator="|" -l' % (display_filters, display_fields)
    return cmdline


#----------------------------------------------------------------------
def __process(infile, args):
    """process a file through tshark for output
    """
    global options
    global config

    # build the basic command line
    tcmdline = __buildtshark()

    # add the input/output file options
    tcmdline += " -r '%s'" % infile
    outfile = os.path.basename(infile)
    outpath = os.path.join(os.path.dirname(infile), options.outpath, outfile) + '.psv'
    tcmdline += " > '%s'" % outpath

    #spawn off a tshark process
    tproc = subprocess.Popen([tcmdline], bufsize=8192, shell=True)
    logger.info("Spawned tshark process (%s): %s" % (tproc.pid, tcmdline))

    return tproc

#----------------------------------------------------------------------
def usage(parser):
    """print usage
    """
    logger.debug("Use -h or --help option for usage informaton.")
    parser.print_help()


#----------------------------------------------------------------------
def main(argv):
    global options
    global config
    global start_time

    start_time = time.strftime("%Y-%m-%d-%H%M%S")

    tprocs = []

    __parsecl()
    __parsecfg()

    for infile in __getfiles(options.inpath, "*.%s" % options.extension):
        p = __process(infile, config)
        tprocs.append(p)

        while len(tprocs) >= options.maxprocs:
            time.sleep(10)
            # we need a temporary list here because the processes list
            # is going to get modified when a process is removed, which will
            # cause a fault on the next indexed lookup.
            tmp_procs = list(tprocs)
            for i in range(len(tmp_procs)):
                ret = tmp_procs[i].poll()
                if ret is not None:
                    index = tprocs.index(tmp_procs[i])
                    logger.info("Process tshark (%s) returned %s" %(tprocs[index].pid, ret))
                    tprocs.remove(tprocs[index])

    # now we need to wait for all the grep processes to end
    logger.info("Waiting for all processes to finish")
    while len(tprocs) > 0:
        # we need a temporary list here because the processes list
        # is going to get modified when a process is removed, which will
        # cause a fault on the next indexed lookup.
        time.sleep(2)
        tmp_procs = list(tprocs)
        for i in range(len(tmp_procs)):
            ret = tmp_procs[i].poll()
            if ret is not None:
                index = tprocs.index(tmp_procs[i])
                logger.info("Process tshark (%s) returned %s" %(tprocs[index].pid, ret))
                tprocs.remove(tprocs[index])

    logger.info("Finished processing")


#----------------------------------------------------------------------
# Set up logging and start the program.
logger = logging.getLogger("jsharklog")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s:%(lineno)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
parser = OptionParser()

if __name__ == '__main__':
    main(sys.argv[1:])
