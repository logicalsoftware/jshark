#!/usr/bin/env python

"""Generate filter and field lists for jshark from wireshark web site.
"""

__author__ = "Jason Sherman (jsherman@data-tactics.com)"
__version__ = "$Revision: .1 $"
__date__ = "$Date: 2011/03/12 $"

import os
import re
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

    parser.add_option("-e", "--extension", dest="extension", default="html", help="input file extension", metavar="EXT")
    parser.add_option("-i", "--inpath", dest="inpath", default="/home/jason/Documents/wireshark/dfref", help="input file path", metavar="FILEORDIR")
    parser.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="log debug output")
    parser.add_option("-o", "--outpath", dest="outpath", default="/home/jason/Documents/ws-out", help="output file path", metavar="FILEORDIR")
    parser.add_option("-r", "--recurse", dest="recurse", default=False, action="store_true", help="recurse into inpath to find more files", metavar="PARSE")
    parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true", help="extra info on stdout")

    (options, args) = parser.parse_args()

    ## mandatory options need to have a sanity check
    __sanitycheck((options.inpath == None), parser, "Error: input path or file not provided")

    if options.outpath == None:
        if os.path.isdir(options.inpath):
            options.outpath = os.path.join(options.inpath, 'ws-out')
        else:
            options.outpath = os.path.dirname(options.inpath)

    if os.path.isdir(options.outpath):
        logger.info('Output directory already exists - %s' % options.outpath)
    else:
        try:
            os.mkdir(options.outpath)
        except OSError:
            logger.info('Error creating directory - %s' % options.outpath)


    if options.debug == True:
        logger.setLevel(logging.DEBUG)

    
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
def main(argv):
    """"""
    global options
    global config
    global start_time

    start_time = time.strftime("%Y-%m-%d-%H%M%S")

    __parsecl()
        
    filter_list = {}
    idx_file = os.path.join(options.inpath, 'index.html')
    f = open(idx_file, 'r')
    for line in f:
        if 'db-lsp' in line:
            pass
        hit = re.search('^[a-zA-Z0-9_-]*:', line)
        if hit is not None:
            filter_list[hit.group().split(':')[0]] = []
    f.close()
            
    for key in filter_list.keys():
        if key == 'cds_solicit':
            pass
        fdir = key[0]

        if ('_' in key or '-' in key):
            hitkey = key.split('_')[0]
            hitkey = hitkey.split('-')[0]
        else:
            hitkey = key

        ffile = os.path.join(options.inpath, fdir, "%s.html" % key)
        try:
            f = open(ffile, 'r')
            for line in f:
                if "<th>Field name</th>" not in line:
                    continue
                else:
                    break

            for line in f:
                hit = re.search('%s[\.a-zA-Z0-9_-]*' % hitkey, line)
                if hit is not None:
                    if hit.group() == key:
                        # we already have the field name
                        pass
                    else:
                        # we really want the field parameters
                        filter_list[key].append(hit.group())
                        
        except:
            pass
        finally:
            f.close()
            
    filters_path = os.path.join(options.outpath, 'jshark.filters')
    fields_path = os.path.join(options.outpath, 'jshark.fields')
    
    try:
       filters_file = open(filters_path, 'w')
       filters_file.write("[filters]\n")
    except:
        logger.error("Could not open filters file - %s" % filters_file)
        
    try:
        fields_file = open(fields_path, 'w')  
        fields_file.write("[fields]\nall: frame.time ip.src eth.src ip.dst eth.dst frame.protocols\n")
    except:
        logger.error("Could not open fields file - %s" % fields_file)
    
    keys = filter_list.keys()
    keys.sort()
    for key in keys:
        filters_file.write("%s: %s\n" % (key, key))
        fields_file.write("%s: %s\n" % (key, " ".join(filter_list[key])))
        
    filters_file.close()
    fields_file.close()
        
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