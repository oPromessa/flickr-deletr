#!/usr/bin/env python

"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-uploader/

    THIS SCRIPT IS PROVIDED WITH NO WARRANTY WHATSOEVER.
    PLEASE REVIEW THE SOURCE CODE TO MAKE SURE IT WILL WORK FOR YOUR NEEDS.
    IF YOU FIND A BUG, PLEASE REPORT IT.

    Some giberish. Please ignore!
    -----------------------------
    Area for my personal notes on on-going work! Please ignore!

    ## Update History
    -----------------
    * Initial version

    ## Recognition
    --------------
    Inspired by:
    * https://github.com/sybrenstuvel/flickrapi
    * http://micampe.it/things/flickruploadr
    * https://github.com/joelmx/flickrUploadr/blob/master/python3/uploadr.py

    ## Pending improvements/Known issues
    ------------------------------------
    * AVOID using deletr when performing massive other operations on flicr.

    ## Programming Remarks
    ----------------------
    * Follow PEP8 coding guidelines. (see http://pep8online.com/checkresult)
    * If using isThisStringUnicode for (something) if test else (other) make
      sure to break lines with \ correctly. Be careful.
    * Use niceprint function to output messages to stdout.
    * Use logging. for CRITICAL, ERROR, WARNING, INFO, DEBUG messages to stderr
    * Some ocasional critical messages are generated with sys.stderr.write()
    * Specific CODING related comments marked with 'CODING'
    * Prefix coding for some output messages:
        *****   Section informative
        ===     Multiprocessing related
       ++     Exceptions handling related
    * As far as my testing goes :) the following errors are handled:
            Flickr reports file not loaded due to error: 5
                [flickr:Error: 5: Filetype was not recognised]
                Might as well log such files and marked them not to be loaded
                again!
            Database is locked
            error setting video date
            error 502: flickrapi
            error 504: flickrapi

    ## README.md
    ------------
    * Check README.md file for (some) more information including:

    ## Description
    ## Features
    ## Requirements
    ## Setup on Synology
    ## Configuration
    ## Usage/Arguments/Options
    ## Task Scheduler (cron)
    ## Recognition
    ## Final remarks
    ## Q&A

"""

# ----------------------------------------------------------------------------
# Import section
#
# Check if it is still required
import httplib
import sys
import argparse
import mimetools
import mimetypes
import os
import time
import sqlite3 as lite
import hashlib
import fcntl
import errno
import subprocess
import re
import ConfigParser
import multiprocessing
import flickrapi
import xml
import os.path
import logging
import pprint


#==============================================================================
# Init code
#
# Python version must be greater than 2.7 for this script to run
#
if sys.version_info < (2, 7):
    sys.stderr.write("This script requires Python 2.7 or newer.\n")
    sys.stderr.write("Current version: " + sys.version + "\n")
    sys.stderr.flush()
    sys.exit(1)
else:
    #Define LOGGING_LEVEL to allow logging even if everything's else is wrong!
    LOGGING_LEVEL = logging.WARNING
    sys.stderr.write('--------- '  + 'Init: ' + ' ---------\n')

# ----------------------------------------------------------------------------
# Constants class
#
# List out the constants to be used
#
class UPLDRConstants:
    """ UPLDRConstants class
    """

    TimeFormat = '%Y.%m.%d %H:%M:%S'
    # For future use...
    # UTF = 'utf-8'
    Version = '2.5.1'

    def __init__(self):
        """ Constructor
        """
        pass

# ----------------------------------------------------------------------------
# Global Variables
#   nutime      = for working with time module (import time)
#   nuflickr    = object for flickr API module (import flickrapi)
#   nulockDB    = multiprocessing Lock for access to Database
#   numutex     = multiprocessing mutex to control access to value nurunning
#   nurunning   = multiprocessing Value to count processed photos
nutime = time
nuflickr = None
nulockDB = None
numutex = None
nurunning = None

# -----------------------------------------------------------------------------
# isThisStringUnicode
#
# Returns true if String is Unicode
#
def isThisStringUnicode(s):
    """
    Determines if a string is Unicode (return True) or not (returns False)
    to allow correct print operations.
    Example:
        print(u'File ' + file.encode('utf-8') + u'...') \
              if isThisStringUnicode(file) else ("File " + file + "...")
    """
    if isinstance(s, unicode):
        return True
    elif isinstance(s, str):
        return False
    else:
        return False

# -----------------------------------------------------------------------------
# niceprint
#
# Print a message with the format:
#   [2017.10.25 22:32:03]:[PRINT   ]:[uploadr] Some Message
#
def niceprint(s):
    """
    Print a message with the format:
        [2017.10.25 22:32:03]:[PID]:[PRINT   ]:[uploadr] Some Message
        Accounts for UTF-8 Messages
    """
    print('[{!s}]:[{!s}][{!s:8s}]:[{!s}] {!s}'.format(
            nutime.strftime(UPLDRConstants.TimeFormat),
            os.getpid(),
            'PRINT',
            'uploadr',
            s.encode('utf-8') if isThisStringUnicode(s) else s))

#==============================================================================
# Read Config from config.ini file
# Obtain configuration from uploadr.ini
# Refer to contents of uploadr.ini for explanation on configuration parameters
config = ConfigParser.ConfigParser()
INIFiles = config.read(os.path.join(os.path.dirname(sys.argv[0]),
                                    "uploadr.ini"))
if not INIFiles:
    sys.stderr.write('[{!s}]:[{!s}][ERROR   ]:[uploadr] '
                     'INI file: [{!s}] not found!.\n'
                     .format(nutime.strftime(UPLDRConstants.TimeFormat),
                             os.getpid(),
                             os.path.join(os.path.dirname(sys.argv[0]),
                                          'uploadr.ini')))
    sys.exit()
if config.has_option('Config', 'FILES_DIR'):
    FILES_DIR = eval(config.get('Config', 'FILES_DIR'))
else:
    FILES_DIR = ""
FLICKR = eval(config.get('Config', 'FLICKR'))
SLEEP_TIME = eval(config.get('Config', 'SLEEP_TIME'))
DRIP_TIME = eval(config.get('Config', 'DRIP_TIME'))
DB_PATH = eval(config.get('Config', 'DB_PATH'))
try:
    TOKEN_CACHE = eval(config.get('Config', 'TOKEN_CACHE'))
# CODING: Should extend this control to other parameters (Enhancement #7)
except (ConfigParser.NoOptionError, ConfigParser.NoOptionError), err:
    sys.stderr.write('[{!s}]:[{!s}][WARNING ]:[uploadr] ({!s}) TOKEN_CACHE '
                     'not defined or incorrect on INI file: [{!s}]. '
                     'Assuming default value [{!s}].\n'
                     .format(nutime.strftime(UPLDRConstants.TimeFormat),
                             os.getpid(),
                             str(err),
                             os.path.join(os.path.dirname(sys.argv[0]),
                                          "uploadr.ini"),
                             os.path.join(os.path.dirname(sys.argv[0]),
                                          "token")))
    TOKEN_CACHE = os.path.join(os.path.dirname(sys.argv[0]), "token")
LOCK_PATH = eval(config.get('Config', 'LOCK_PATH'))
TOKEN_PATH = eval(config.get('Config', 'TOKEN_PATH'))
EXCLUDED_FOLDERS = eval(config.get('Config', 'EXCLUDED_FOLDERS'))
IGNORED_REGEX = [re.compile(regex) for regex in \
                 eval(config.get('Config', 'IGNORED_REGEX'))]
ALLOWED_EXT = eval(config.get('Config', 'ALLOWED_EXT'))
RAW_EXT = eval(config.get('Config', 'RAW_EXT'))
FILE_MAX_SIZE = eval(config.get('Config', 'FILE_MAX_SIZE'))
MANAGE_CHANGES = eval(config.get('Config', 'MANAGE_CHANGES'))
RAW_TOOL_PATH = eval(config.get('Config', 'RAW_TOOL_PATH'))
CONVERT_RAW_FILES = eval(config.get('Config', 'CONVERT_RAW_FILES'))
FULL_SET_NAME = eval(config.get('Config', 'FULL_SET_NAME'))
SOCKET_TIMEOUT = eval(config.get('Config', 'SOCKET_TIMEOUT'))
MAX_UPLOAD_ATTEMPTS = eval(config.get('Config', 'MAX_UPLOAD_ATTEMPTS'))
# LOGGING_LEVEL = eval(config.get('Config', 'LOGGING_LEVEL'))
LOGGING_LEVEL = (config.get('Config', 'LOGGING_LEVEL')
                 if config.has_option('Config', 'LOGGING_LEVEL')
                 else logging.WARNING)

#==============================================================================
# Logging
#
# Obtain configuration level from Configuration file.
# If not available or not valid assume WARNING level and notify of that fact.
# Two uses:
#   Simply log message at approriate level
#       logging.warning('Status: {!s}'.format('Setup Complete'))
#   Control additional specific output to stderr depending on level
#       if LOGGING_LEVEL <= logging.INFO:
#            logging.info('Output for {!s}:'.format('uploadResp'))
#            logging.info(xml.etree.ElementTree.tostring(
#                                                    addPhotoResp,
#                                                    encoding='utf-8',
#                                                    method='xml'))
#            <generate any further output>
#   Control additional specific output to stdout depending on level
#       if LOGGING_LEVEL <= logging.INFO:
#            niceprint ('Output for {!s}:'.format('uploadResp'))
#            xml.etree.ElementTree.dump(uploadResp)
#            <generate any further output>
#
if (int(LOGGING_LEVEL) if str.isdigit(LOGGING_LEVEL) else 99) not in [
                        logging.NOTSET,
                        logging.DEBUG,
                        logging.INFO,
                        logging.WARNING,
                        logging.ERROR,
                        logging.CRITICAL]:
    LOGGING_LEVEL = logging.WARNING
    sys.stderr.write('[{!s}]:[WARNING ]:[uploadr] LOGGING_LEVEL '
                     'not defined or incorrect on INI file: [{!s}]. '
                     'Assuming WARNING level.\n'.format(
                            nutime.strftime(UPLDRConstants.TimeFormat),
                            os.path.join(os.path.dirname(sys.argv[0]),
                                         "uploadr.ini")))
# Force conversion of LOGGING_LEVEL into int() for later use in conditionals
LOGGING_LEVEL = int(LOGGING_LEVEL)
logging.basicConfig(stream=sys.stderr,
                    level=int(LOGGING_LEVEL),
                    datefmt=UPLDRConstants.TimeFormat,
                    format='[%(asctime)s]:[%(processName)s][%(levelname)-8s]'
                           ':[%(name)s] %(message)s')
#==============================================================================
# Test section for logging.
# CODING: Uncomment for testing.
#   Only applicable if LOGGING_LEVEL is INFO or below (DEBUG, NOTSET)
#
# if LOGGING_LEVEL <= logging.INFO:
#     logging.info(u'sys.getfilesystemencoding:[{!s}]'.
#                     format(sys.getfilesystemencoding()))
#     logging.info('LOGGING_LEVEL Value: {!s}'.format(LOGGING_LEVEL))
#     if LOGGING_LEVEL <= logging.WARNING:
#         logging.critical('Message with {!s}'.format(
#                                     'CRITICAL UNDER min WARNING LEVEL'))
#         logging.error('Message with {!s}'.format(
#                                     'ERROR UNDER min WARNING LEVEL'))
#         logging.warning('Message with {!s}'.format(
#                                     'WARNING UNDER min WARNING LEVEL'))
#         logging.info('Message with {!s}'.format(
#                                     'INFO UNDER min WARNING LEVEL'))
if LOGGING_LEVEL <= logging.INFO:
    niceprint('Pretty Print for {!s}'.format(
                                'FLICKR Configuration:'))
    pprint.pprint(FLICKR)

#==============================================================================
# CODING: Search 'Main code' section for code continuation after definitions

# ----------------------------------------------------------------------------
# FileWithCallback class
#
# For use with flickrapi upload for showing callback progress information
# Check function callback definition
#
class FileWithCallback(object):
    def __init__(self, filename, callback):
        self.file = open(filename, 'rb')
        self.callback = callback
        # the following attributes and methods are required
        self.len = os.path.getsize(filename)
        self.fileno = self.file.fileno
        self.tell = self.file.tell

    def read(self, size):
        if self.callback:
            self.callback(self.tell() * 100 // self.len)
        return self.file.read(size)

# ----------------------------------------------------------------------------
# callback
#
# For use with flickrapi upload for showing callback progress information
# Check function FileWithCallback definition
# Uses global args.verbose parameter
#
def callback(progress):
    # only print rounded percentages: 0, 10, 20, 30, up to 100
    # adapt as required
    # if ((progress % 10) == 0):
    # if verbose option is set
    if (args.verbose):
        if ((progress % 40) == 0):
            print(progress)

# ----------------------------------------------------------------------------
# Uploadr class
#
#   Main class for uploading of files.
#
class Uploadr:
    """ Uploadr class
    """

    # Flicrk connection authentication token
    token = None
    perms = ""

    def __init__(self):
        """ Constructor
        """
        self.token = self.getCachedToken()

    # -------------------------------------------------------------------------
    # niceprocessedfiles
    #
    # Nicely print number of processed files
    #
    def niceprocessedfiles(self, count, total):
        """
        niceprocessedfiles

        count = Nicely print number of processed files rounded to 100's
        total = if true shows the total (to be used at the end of processing)
        """

        if not total:
            if (count % 100 == 0):
                niceprint('\t' +
                          str(count) +
                          ' files processed (uploaded, md5ed '
                          'or timestamp checked)')
        else:
            if (count % 100 > 0):
                niceprint('\t' +
                          str(count) +
                          ' files processed (uploaded, md5ed '
                          'or timestamp checked)')

    # -------------------------------------------------------------------------
    # authenticate
    #
    # Authenticates via flickrapi on flickr.com
    #
    def authenticate(self):
        """
        Authenticate user so we can upload files
        """
        global nuflickr

        # instantiate nuflickr for connection to flickr via flickrapi
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                       FLICKR["secret"],
                                       token_cache_location=TOKEN_CACHE)
        # Get request token
        niceprint('Getting new token.')
        nuflickr.get_request_token(oauth_callback='oob')

        # Show url. Copy and paste it in your browser
        authorize_url = nuflickr.auth_url(perms=u'delete')
        print(authorize_url)

        # Prompt for verifier code from the user
        verifier = unicode(raw_input('Verifier code: '))

        if LOGGING_LEVEL <= logging.WARNING:
            logging.warning('Verifier: {!s}'.format(verifier))

        # Trade the request token for an access token
        print(nuflickr.get_access_token(verifier))

        if LOGGING_LEVEL <= logging.WARNING:
            logging.critical('{!s} with {!s} permissions: {!s}'.format(
                                        'Check Authentication',
                                        'delete',
                                        nuflickr.token_valid(perms='delete')))
            logging.critical('Token Cache: {!s}', nuflickr.token_cache.token)

    # -------------------------------------------------------------------------
    # getCachedToken
    #
    # If available, obtains the flicrapi Cached Token from local file.
    # Saves the token on the Class global variable "token"
    #
    def getCachedToken(self):
        """
        Attempts to get the flickr token from disk.
        """
        global nuflickr

        logging.info('Obtaining Cached token')
        logging.debug('TOKEN_CACHE:[{!s}]'.format(TOKEN_CACHE))
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                       FLICKR["secret"],
                                       token_cache_location=TOKEN_CACHE)

        try:
            # CODING: If token is cached does it make sense to check
            # if permissions are correct?
            if nuflickr.token_valid(perms='delete'):
                if LOGGING_LEVEL <= logging.INFO:
                    logging.info('Cached token obtained: {!s}'
                                 .format(nuflickr.token_cache.token))
                return nuflickr.token_cache.token
            else:
                logging.info('Token Non-Existant.')
                return None
        except:
            niceprint('Unexpected error:' + sys.exc_info()[0])
            raise

    # -------------------------------------------------------------------------
    # checkToken
    #
    # If available, obtains the flicrapi Cached Token from local file.
    #
    # Returns
    #   true: if global token is defined and allows flicrk 'delete' operation
    #   false: if global token is not defined or flicrk 'delete' is not allowed
    #
    def checkToken(self):
        """ checkToken
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        """
        global nuflickr

        logging.warning('checkToken is (self.token is None):[{!s}]'
                        .format(self.token is None))

        if (self.token is None):
            return False
        else:
            nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                           FLICKR["secret"],
                                           token_cache_location=TOKEN_CACHE)
            if nuflickr.token_valid(perms='delete'):
                return True
            else:
                logging.warning('Authentication required.')
                return False

    #--------------------------------------------------------------------------
    # removeIgnoreMedia
    #
    # When EXCLUDED_FOLDERS defintion changes. You can run the -g
    # or --remove-ignored option in order to remove files previously loaded
    # files from
    #
    def removeIgnoredMedia(self):
        niceprint('*****Removing ignored files*****')

        if (not flick.checkToken()):
            flick.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            for row in rows:
                # row[1] is par
                if (self.isFileIgnored(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)

        # Closing DB connection
        if con is not None:
            con.close()

        niceprint('*****Completed ignored files*****')

    #--------------------------------------------------------------------------
    # removeDeleteMedia
    #
    # Remove files deleted at the local source
    #
    def removeDeletedMedia(self):
        """
        Remove files deleted at the local source
            loop through database
            check if file exists
            if exists, continue
            if not exists, delete photo from fickr (flickr.photos.delete.html)
        """

        niceprint('*****Removing deleted files*****')

        # XXX MSP Changed from self to flick
        # if (not self.checkToken()):
        #     self.authenticate()
        if (not flick.checkToken()):
            flick.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            niceprint(str(len(rows)) + ' will be checked for Removal...')

            count = 0
            for row in rows:
                if (not os.path.isfile(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)
                    logging.warning('deleteFile result: {!s}'.format(success))
                    count = count + 1
                    if (count % 3 == 0):
                        niceprint('\t' + str(count) + ' files removed...')
            if (count % 100 > 0):
                niceprint('\t' + str(count) + ' files removed.')

        # Closing DB connection
        if con is not None:
            con.close()

        niceprint('*****Completed deleted files*****')

    #--------------------------------------------------------------------------
    # upload
    #
    #  Main cycle for file upload
    #
    def upload(self):
        """ upload
        Add files to flickr and into their sets(Albums)
        If enabled CHANGE_MEDIA, checks for file changes and updates flickr
        """

        global nulockDB
        global numutex
        global nurunning

        niceprint("*****Uploading files*****")

        allMedia = self.grabNewFiles()
        # If managing changes, consider all files
        if MANAGE_CHANGES:
            logging.warning('MANAGED_CHANGES is True. Reviewing allMedia.')
            changedMedia = allMedia

        # If not, then get just the new and missing files
        else:
            logging.warning('MANAGED_CHANGES is False. Reviewing only '
                            'changedMedia.')
            con = lite.connect(DB_PATH)
            con.text_factory = str
            with con:
                cur = con.cursor()
                cur.execute("SELECT path FROM files")
                existingMedia = set(file[0] for file in cur.fetchall())
                changedMedia = set(allMedia) - existingMedia

        changedMedia_count = len(changedMedia)
        niceprint('Found ' + str(changedMedia_count) + ' files to upload.')

        if (args.bad_files):
            # Cater for bad files
            con = lite.connect(DB_PATH)
            con.text_factory = str
            with con:
                cur = con.cursor()
                cur.execute("SELECT path FROM badfiles")
                badMedia = set(file[0] for file in cur.fetchall())
                changedMedia = set(changedMedia) - badMedia
                logging.debug('len(badMedia)'.format(len(badMedia)))

            changedMedia_count = len(changedMedia)
            niceprint('Removing ' + len(badMedia) + ' badfiles. Found ' +
                      str(changedMedia_count) + ' files to upload.')

        # running in multi processing mode
        if (args.processes and args.processes > 0):
            logging.debug('Running Pool of [{!s}] processes...'
                          .format(args.processes))
            logging.debug('__name__:[{!s}] to prevent recursive calling)!'
                          .format(__name__))

            # To prevent recursive calling, check if __name__ == '__main__'
            if __name__ == '__main__':
                l = multiprocessing.Lock()

                logging.debug('===Multiprocessing=== Setting up logger!')
                multiprocessing.log_to_stderr()
                logger = multiprocessing.get_logger()
                logger.setLevel(LOGGING_LEVEL)

                logging.debug('===Multiprocessing=== Lock defined!')

                # -------------------------------------------------------------------------
                # chunk
                #
                # Divides an iterable in slices/chunks of size size
                #
                from itertools import islice

                def chunk(it, size):
                    """
                        Divides an iterable in slices/chunks of size size
                    """
                    it = iter(it)
                    # lambda: creates a returning expression function
                    # whic returns slices
                    # iter, with the second argument () stops creating
                    # iterators when it reaches the end
                    return iter(lambda: tuple(islice(it, size)), ())

                uploadPool = []
                nulockDB = multiprocessing.Lock()
                nurunning = multiprocessing.Value('i', 0)
                numutex = multiprocessing.Lock()

                # for i in range(int(args.processes)):

                sz = (len(changedMedia) / int(args.processes)) \
                     if ((len(changedMedia) / int(args.processes)) > 0) \
                     else 1

                logging.debug('len(changedMedia):[{!s}] '
                              'int(args.processes):[{!s}] '
                              'sz per process:[{!s}]'
                              .format(len(changedMedia),
                                      int(args.processes),
                                      sz))

                # Split the Media in chunks to distribute accross Processes
                for nuChangeMedia in chunk(changedMedia, sz):
                    logging.info('===Actual/Planned Chunk size: [{!s}]/[{!s}]'
                                 .format(len(nuChangeMedia), sz))
                    logging.debug(type(nuChangeMedia))

                    logging.debug('===Job/Task Process: Creating...')
                    uploadTask = multiprocessing.Process(
                                        target=self.uploadFileX,
                                        args=(nulockDB,
                                              nurunning,
                                              numutex,
                                              nuChangeMedia,))
                    uploadPool.append(uploadTask)
                    logging.debug('===Job/Task Process: Starting...')
                    uploadTask.start()
                    logging.debug('===Job/Task Process: Started')

                # Check status of jobs/tasks in the Process Pool
                if LOGGING_LEVEL <= logging.DEBUG:
                    logging.debug('===Checking Processes launched/status:')
                    for j in uploadPool:
                        niceprint('%s.is_alive = %s' % (j.name, j.is_alive()))

                # Regularly print status of jobs/tasks in the Process Pool
                # Exits when all jobs/tasks are done.
                while (True):
                    if not (any(multiprocessing.active_children())):
                        logging.debug('===No active children Processes.')
                        break
                    for p in multiprocessing.active_children():
                        logging.debug('==={!s}.is_alive = {!s}'
                                      .format(p.name, p.is_alive()))
                        uploadTaskActive = p
                    logging.info('===Will wait for 60 on {!s}.is_alive = {!s}'
                                 .format(uploadTaskActive.name,
                                         uploadTaskActive.is_alive()))
                    niceprint('===Will wait for 60 on {!s}.is_alive = {!s}'
                              .format(uploadTaskActive.name,
                                      uploadTaskActive.is_alive()))

                    uploadTaskActive.join(timeout=60)
                    logging.info('===Waited for 60s on {!s}.is_alive = {!s}'
                                 .format(uploadTaskActive.name,
                                         uploadTaskActive.is_alive()))
                    niceprint('===Waited for 60s on {!s}.is_alive = {!s}'
                              .format(uploadTaskActive.name,
                                      uploadTaskActive.is_alive()))

                # Wait for join all jobs/tasks in the Process Pool
                # All should be done by now!
                for j in uploadPool:
                    j.join()
                    niceprint('===%s (is alive: %s).exitcode = %s' %
                              (j.name, j.is_alive(), j.exitcode))

                logging.warning('===Multiprocessing=== pool joined!'
                                'All processes finished.')
            else:
                niceprint('Pool not in __main__ process. '
                          'Windows or recursive?'
                          'Not possible to run Multiprocessing mode')
        # running in single processing mode
        else:
            count = 0
            for i, file in enumerate(changedMedia):
                logging.debug('file:[{!s}] type(file):[{!s}]'
                              .format(file, type(file)))
                # lock parameter not used (set to None) under single processing
                success = self.uploadFile(lock=None, file=file)
                if args.drip_feed and success and i != changedMedia_count - 1:
                    print("Waiting " +
                          str(DRIP_TIME) +
                          " seconds before next upload")
                    nutime.sleep(DRIP_TIME)
                count = count + 1
                self.niceprocessedfiles(count, False)
            self.niceprocessedfiles(count, True)

        niceprint("*****Completed uploading files*****")

    #--------------------------------------------------------------------------
    # convertRawFiles
    #
    def convertRawFiles(self):

        # CODING: Not tested. Not in use at this time. I do not use RAW Files.
        # Also you need Image-ExifTool-9.69 or similar installed.
        # Check INI config file for and make sure you keep
        # CONVERT_RAW_FILES = False
        # Change and use at your own risk at this time.

        """ convertRawFiles
        """
        if (not CONVERT_RAW_FILES):
            return

        niceprint('*****Converting files*****')
        for ext in RAW_EXT:
            print(u'About to convert files with extension: ' +
                  ext.encode('utf-8') + u' files.') \
                  if isThisStringUnicode(ext) \
                  else ("About to convert files with extension: " +
                        ext + " files.")

            for dirpath, dirnames, filenames in os.walk(
                                                unicode(FILES_DIR, 'utf-8'),
                                                followlinks=True):
                if '.picasaoriginals' in dirnames:
                    dirnames.remove('.picasaoriginals')
                if '@eaDir' in dirnames:
                    dirnames.remove('@eaDir')
                for f in filenames:

                    fileExt = f.split(".")[-1]
                    filename = f.split(".")[0]
                    if (fileExt.lower() == ext):

                        if (not os.path.exists(dirpath + "/" +
                                               filename + ".JPG")):
                            if isThisStringUnicode(dirpath):
                                if isThisStringUnicode(f):
                                    print(u'About to create JPG from raw ' +
                                          dirpath.encode('utf-8') +
                                          u'/' +
                                          f.encode('utf-8'))
                                else:
                                    print(u'About to create JPG from raw ' +
                                          dirpath.encode('utf-8') +
                                          u'/' +
                                          f)
                            elif isThisStringUnicode(f):
                                print("About to create JPG from raw " +
                                      dirpath +
                                      "/" +
                                      f.encode('utf-8'))
                            else:
                                print("About to create JPG from raw " +
                                      dirpath + "/" + f)

                            flag = ""
                            if ext is "cr2":
                                flag = "PreviewImage"
                            else:
                                flag = "JpgFromRaw"

                            command = RAW_TOOL_PATH + "exiftool -b -" + flag +\
                                      " -w .JPG -ext " + ext + " -r '" +\
                                      dirpath + "/" +\
                                      filename + "." + fileExt + "'"
                            logging.info(command)

                            p = subprocess.call(command, shell=True)

                        if (not os.path.exists(dirpath + "/" +
                                               filename + ".JPG_original")):
                            if isThisStringUnicode(dirpath):
                                if isThisStringUnicode(f):
                                    print(u'About to copy tags from ' +
                                          dirpath.encode('utf-8') +
                                          u'/' +
                                          f.encode('utf-8') +
                                          u' to JPG.')
                                else:
                                    print(u'About to copy tags from ' +
                                          dirpath.encode('utf-8') +
                                          u'/' +
                                          f +
                                          " to JPG.")
                            elif isThisStringUnicode(f):
                                print("About to copy tags from " +
                                      dirpath +
                                      "/" +
                                      f.encode('utf-8') +
                                      u' to JPG.')
                            else:
                                print("About to copy tags from " +
                                      dirpath +
                                      "/" +
                                      f +
                                      " to JPG.")

                            command = RAW_TOOL_PATH +\
                                      "exiftool -tagsfromfile '" +\
                                      dirpath + "/" + f +\
                                      "' -r -all:all -ext JPG '" +\
                                      dirpath + "/" + filename + ".JPG'"
                            logging.info(command)

                            p = subprocess.call(command, shell=True)

                            print("Finished copying tags.")

            print(u'Finished converting files with extension:' +
                  ext.encode('utf-8') + u'.') \
                  if isThisStringUnicode(ext) \
                  else ("Finished converting files with extension:" +
                        ext + ".")

        niceprint('*****Completed converting files*****')

    #--------------------------------------------------------------------------
    # grabNewFiles
    #
    def grabNewFiles(self):
        """ grabNewFiles

            Select files from FILES_DIR taking into consideration
            EXCLUDED_FOLDERS and IGNORED_REGEX filenames.
            Returns sorted file list.
        """

        files = []
        for dirpath, dirnames, filenames in\
                os.walk(unicode(FILES_DIR, 'utf-8'), followlinks=True):
            for f in filenames:
                filePath = os.path.join(dirpath, f)
                if self.isFileIgnored(filePath):
                    logging.info('File {!s} in EXCLUDED_FOLDERS:'
                                  .format(filePath.encode('utf-8')))
                    continue
                if any(ignored.search(f) for ignored in IGNORED_REGEX):
                    logging.info('File {!s} in IGNORED_REGEX:'
                                  .format(filePath.encode('utf-8')))
                    continue
                ext = os.path.splitext(os.path.basename(f))[1][1:].lower()
                if ext in ALLOWED_EXT:
                    fileSize = os.path.getsize(dirpath + "/" + f)
                    if (fileSize < FILE_MAX_SIZE):
                        files.append(
                            os.path.normpath(
                                dirpath.encode('utf-8') +
                                "/" +
                                f.encode(' utf-8')).replace("'", "\'"))
                    else:
                        niceprint('Skipping file due to size restriction: ' +
                                  (os.path.normpath(dirpath.encode('utf-8') +
                                                    '/' +
                                                    f.encode('utf-8'))))
        files.sort()
        if LOGGING_LEVEL <= logging.DEBUG:
            niceprint('Pretty Print Output for {!s}:'.format('files'))
            pprint.pprint(files)

        return files

    #--------------------------------------------------------------------------
    # isFileIgnored
    #
    # Check if a filename is within the list of EXCLUDED_FOLDERS. Returns:
    #   true = if filename's folder is within one of the EXCLUDED_FOLDERS
    #   false = if filename's folder not on one of the EXCLUDED_FOLDERS
    #
    def isFileIgnored(self, filename):
        for excluded_dir in EXCLUDED_FOLDERS:
            if excluded_dir in os.path.dirname(filename):
                return True

        return False

    #--------------------------------------------------------------------------
    # uploadFileX
    #
    # uploadFile wrapper for multiprocessing purposes
    #
    def uploadFileX(self, lock, running, mutex, filelist):
        """ uploadFileX

            Wrapper function for multiprocessing support to call uploadFile
            with a chunk of the files.
            lock = for database access control in multiprocessing
            running = shared value to count processed files in multiprocessing
            mutex = for running access control in multiprocessing
        """

        for i, f in enumerate(filelist):
            logging.warning('===Current element of Chunk: [{!s}][{!s}]'
                            .format(i, f))
            self.uploadFile(lock, f)

            # no need to check for
            # (args.processes and args.processes > 0):
            # as uploadFileX is already multiprocessing

            logging.debug('===Multiprocessing=== in.mutex.acquire(w)')
            mutex.acquire()
            running.value += 1
            xcount = running.value
            mutex.release()
            logging.warning('===Multiprocessing=== out.mutex.release(w)')

            # Show number of files processed so far
            self.niceprocessedfiles(xcount, False)
            
        # Show number of total files processed
        self.niceprocessedfiles(xcount, True)

    #--------------------------------------------------------------------------
    # uploadFile
    #
    # uploads a file into flickr
    #   lock = parameter for multiprocessing control of access to DB.
    #          if args.processes = 0 then lock can be None as it is not used
    #   file = fie to be uploaded
    #
    def uploadFile(self, lock, file):
        """ uploadFile
        uploads file into flickr

        May run in single or multiprocessing mode

        lock = parameter for multiprocessing control of access to DB.
               (if args.processes = 0 then lock can be None as it is not used)
        running = counter of number of processed files in multiprocessing
        mutex = multiprocessing control of access to running.
        file = fie to be uploaded
        """

        global nuflickr

        if (args.dry_run is True):
            print(u'file.type=' + str(type(file)).encode('utf-8'))
            print(u'Dry Run Uploading ', file, '...')
            return True

        if (args.verbose):
            niceprint(u'Uploading file:[{!s}]...' + file.encode('utf-8')) \
                if isThisStringUnicode(file) \
                else ('Uploading file:[{!s}]...' + file)

        success = False
        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            logging.debug('Output for {!s}:'.format('uploadFILE SELECT'))
            logging.debug('{!s}: {!s}'.format('SELECT rowid,files_id,path,'
                                              'set_id,md5,tagged,'
                                              'last_modified FROM '
                                              'files WHERE path = ?',
                                              file))

            cur.execute('SELECT rowid,files_id,path,set_id,md5,tagged,'
                        'last_modified FROM files WHERE path = ?', (file,))
            row = cur.fetchone()
            logging.debug('row {!s}:'.format(row))

            # use file modified timestamp to check for changes
            last_modified = os.stat(file).st_mtime
            if row is None:
                niceprint(u'Uploading ' + file.encode('utf-8') + u'...') \
                          if isThisStringUnicode(file) \
                          else ("Uploading " + file + "...")

                if FULL_SET_NAME:
                    setName = os.path.relpath(os.path.dirname(file),
                                              unicode(FILES_DIR, 'utf-8'))
                else:
                    head, setName = os.path.split(os.path.dirname(file))
                try:
                    niceprint(u'setName: ' + setName.encode('utf-8')) \
                              if isThisStringUnicode(setName) \
                              else ('setName: ' + setName)
                    if isThisStringUnicode(file):
                        photo = ('photo', file.encode('utf-8'),
                                 open(file, 'rb').read())
                    else:
                        photo = ('photo', file,
                                 open(file, 'rb').read())
                    if args.title:  # Replace
                        FLICKR["title"] = args.title
                    if args.description:  # Replace
                        FLICKR["description"] = args.description
                    if args.tags:  # Append a space to later add -t TAGS
                        FLICKR["tags"] += " "
                        if args.verbose:
                            niceprint('TAGS:[{} {}]'
                                      .format(FLICKR["tags"],
                                             args.tags).replace(',', ''))

                    # if FLICKR["title"] is empty...
                    # if filename's exif title is empty...
                    #   Can't check without import exiftool
                    # set it to filename OR do not load it up in order to
                    # allow flickr.com itself to set it up
                    # NOTE: an empty title forces flickrapi/auth.py
                    # code like 280 to encode into utf-8 the filename
                    # this causes an error
                    # UnicodeDecodeError: 'ascii' codec can't decode byte 0xc3
                    # in position 11: ordinal not in range(128)
                    # Worked around it by forcing the title to filename
                    if FLICKR["title"] == "":
                        path_filename, title_filename = os.path.split(file)
                        logging.info('path:[{!s}] '
                                        'filename:[{!s}] '
                                        'ext=[{!s}]'.format(
                                            path_filename,
                                            title_filename,
                                            os.path.splitext(
                                                    title_filename)[1]))
                        title_filename = os.path.splitext(title_filename)[0]
                        logging.warning('title_name:[{!s}] '
                                        .format(title_filename))
                    else:
                        title_filename = FLICKR["title"]
                        logging.warning('title '
                                        'from INI file:[{!s}]'
                                        .format(title_filename))

                    file_checksum = self.md5Checksum(file)

                    # Perform actual upload of the file
                    res = None
                    search_result = None
                    for x in range(0, MAX_UPLOAD_ATTEMPTS):
                        try:
                            logging.warning('Uploading/Reuploading '
                                            '[{!s}/{!s} attempts].'
                                            .format(x, MAX_UPLOAD_ATTEMPTS))
                            if (x > 0):
                                niceprint(u'Reuploading ' +
                                          file.encode('utf-8') +
                                          u'...') \
                                          if isThisStringUnicode(file) \
                                          else ('Reuploading ' + file + '...')
                            # Upload file to Flickr
                            if FLICKR["title"] == "":
                                # replace commas from tags and checksum tags
                                # to avoid tags conflicts
                                uploadResp = nuflickr.upload(
                                        filename=file,
                                        fileobj=FileWithCallback(file,
                                                                 callback),
                                        title=title_filename,
                                        description=str(FLICKR["description"]),
                                        tags='{} checksum:{} {}'
                                             .format(
                                                    FLICKR["tags"],
                                                    file_checksum,
                                                    args.tags \
                                                    if args.tags \
                                                    else ''
                                                    ).replace(',', ''),
                                        is_public=str(FLICKR["is_public"]),
                                        is_family=str(FLICKR["is_family"]),
                                        is_friend=str(FLICKR["is_friend"])
                                        )
                            else:
                                uploadResp = nuflickr.upload(
                                        filename=file,
                                        fileobj=FileWithCallback(file,
                                                                 callback),
                                        title=str(FLICKR["title"]),
                                        description=str(FLICKR["description"]),
                                        tags='{} checksum:{} {}'
                                             .format(
                                                    FLICKR["tags"],
                                                    file_checksum,
                                                    args.tags \
                                                    if args.tags \
                                                    else ''
                                                    ).replace(',', ''),
                                        is_public=str(FLICKR["is_public"]),
                                        is_family=str(FLICKR["is_family"]),
                                        is_friend=str(FLICKR["is_friend"])
                                        )

                            logging.info('uploadResp: ')
                            logging.info(xml.etree.ElementTree.tostring(
                                                uploadResp,
                                                encoding='utf-8',
                                                method='xml'))
                            logging.warning('upload_result:[{!s}]'
                                            .format(self.isGood(uploadResp)))

                            # Save photo_id returned from Flickr upload
                            photo_id = uploadResp.findall('photoid')[0].text
                            logging.warning('Uploaded photo_id=[{!s}] Ok.'
                                            'Will check for issues ('
                                            'duplicates or wrong checksum)'
                                            .format(photo_id))

                            search_result = None
                            break

                            # Perform search for photo with checksum to
                            # confirm loaded was fully okay
                            # SEARCH DUPLICATED!!!
                            # if LOGGING_LEVEL <= logging.DEBUG:
                            #     search_result = self.photos_search(
                            #                                 file_checksum)
                            #     logging.info('search_result:[{!s}]'
                            #                  .format(self
                            #                          .isGood(search_result)))

                        # Exceptions for flickr.upload function call...
                        except (IOError, httplib.HTTPException):
                            niceprint('+++ #01 Caught IOError, HTTP expcetion')
                            niceprint('Sleep 10 and check if file is '
                                      'already uploaded')
                            nutime.sleep(10)

                            # on error, check if exists a photo
                            # with file_checksum
                            search_result = self.photos_search(file_checksum)
                            if not self.isGood(search_result):
                                raise IOError(search_result)

                            # if int(search_result["photos"]["total"]) == 0:
                            if int(search_result.find('photos')
                                   .attrib['total']) == 0:
                                if x == MAX_UPLOAD_ATTEMPTS - 1:
                                    niceprint('Reached maximum number '
                                              'of attempts to upload, '
                                              'file: [{!s}]'.format(file))
                                    raise ValueError('Reached maximum number '
                                                     'of attempts to upload, '
                                                     'skipping')
                                niceprint('Not found, reuploading '
                                          '[{!s}/{!s} attempts].'
                                          .format(x, MAX_UPLOAD_ATTEMPTS))
                                continue

                            if int(search_result.find('photos')
                                   .attrib['total']) > 1:
                                raise IOError('More then one file with same '
                                              'checksum! Any collisions? ' +
                                              search_result)

                            if int(search_result.find('photos')
                                   .attrib['total']) == 1:
                                niceprint('Found, continuing with next image.')
                                break

                    # Error on upload and search for photo not performed/empty
                    if not search_result and not self.isGood(uploadResp):
                        niceprint('A problem occurred while attempting to '
                                    'upload the file: ' +
                                    file.encode('utf-8')) \
                                    if isThisStringUnicode(file) \
                                    else ('A problem occurred while '
                                          'attempting to upload the file: ' +
                                          file)
                        raise IOError(uploadResp)

                    # Successful update
                    niceprint(u'Successfully uploaded the file ' +
                              file.encode('utf-8')) \
                              if isThisStringUnicode(file) \
                              else ("Uploading " + file + "...")

                    # Save file_id... from uploadresp or search_result
                    if search_result:
                        file_id = search_result.find('photos')\
                                    .findall('photo')[0].attrib['id']
                        # file_id = uploadResp.findall('photoid')[0].text
                        logging.warning('Output for {!s}:'
                                        .format('seacrh_result'))
                        logging.warning(xml.etree.ElementTree.tostring(
                                            search_result,
                                            encoding='utf-8',
                                            method='xml'))
                    else:
                        # Successful update given that search_result is None
                        file_id = uploadResp.findall('photoid')[0].text
                        # CODING no need for int()???
                        # file_id = int(str(uploadResp
                        #                   .findall('photoid')[0].text))
                        logging.warning('Output for {!s}:'
                                        .format('uploadResp'))
                        logging.warning(xml.etree.ElementTree.tostring(
                                            uploadResp,
                                            encoding='utf-8',
                                            method='xml'))

                    logging.warning('File_id=[{!s}]'.format(file_id))

                    # Add to db the file uploaded
                    # Control for when running multiprocessing set locking
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing=== in.lock.acquire')
                        lock.acquire()
                        logging.warning('===Multiprocessing=== '
                                        'out.lock.acquire')

                    cur.execute(
                        'INSERT INTO files (files_id, path, md5, '
                        'last_modified, tagged) VALUES (?, ?, ?, ?, 1)',
                        (file_id, file, file_checksum, last_modified))

                    # Control for when running multiprocessing release locking
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing=== in.lock.release')
                        lock.release()
                        logging.warning('===Multiprocessing=== '
                                        'out.lock.release')

                    # Update Date/Time on Flickr for Video files
                    filetype = mimetypes.guess_type(file)
                    logging.info('filetype:[{!s}]:'.format(filetype[0])) \
                                if not (filetype[0] is None) \
                                else ('filetype is None!!!')

                    # update video date/time TAKEN has Flickr does not read it
                    # correctly from the video file itself.
                    if (not filetype[0] is None) and ('video' in filetype[0]):
                        res_set_date = None
                        video_date = nutime.strftime(
                                        '%Y-%m-%d %H:%M:%S',
                                        nutime.localtime(last_modified))
                        logging.info('video_date:[{!s}]'.format(video_date))

                        try:
                            res_set_date = flick.photos_set_dates(
                                                file_id,
                                                video_date)
                            if self.isGood(res_set_date):
                                niceprint("Set date ok")
                        except (IOError, ValueError, httplib.HTTPException):
                            print(str(sys.exc_info()))
                            print("Error setting date")
                            raise
                        if not self.isGood(res_set_date):
                            raise IOError(res_set_date)
                        niceprint(u'Successfully set date for pic number: ' +
                                  file.encode('utf-8') +
                                  u' date:' +
                                  video_date) \
                                  if isThisStringUnicode(file) \
                                  else ('Successfully set date for pic '
                                        'number: ' +
                                        file +
                                        ' date:' +
                                        video_date)
                    success = True
                except flickrapi.exceptions.FlickrError as ex:
                    niceprint('+++ #02 Caught flickrapi exception')
                    niceprint('Error code: [{!s}]'.format(ex.code))
                    niceprint('Error code: [{!s}]'.format(ex))
                    niceprint(str(sys.exc_info()))
                    # Error code: [5]
                    # Error code: [Error: 5: Filetype was not recognised]
                    if (format(ex.code) == '5') and (args.bad_files):
                        # Add to db the file NOT uploaded
                        # Control for when running multiprocessing set locking
                        logging.info('Bad file:[{!s}]'.format(file))
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== badfiles'
                                          'in.lock.acquire')
                            lock.acquire()
                            logging.warning('===Multiprocessing=== badfiles'
                                            'out.lock.acquire')
                        # files_id column is autoincrement. No need to specify
                        cur.execute(
                          'INSERT INTO badfiles ( path, md5, '
                          'last_modified, tagged) VALUES (?, ?, ?, 1)',
                          (file, file_checksum, last_modified))
                        # Control for when running multiprocessing
                        # release locking
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== badfiles'
                                          'in.lock.release')
                            lock.release()
                            logging.warning('===Multiprocessing=== badfiles'
                                            'out.lock.release')

                except lite.Error as e:
                    print('A DB error occurred: %s' % e.args[0])
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                        lock.release()
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                    return False

            elif (MANAGE_CHANGES):
                # we have a file from disk which is found on the database also
                # row[6] is last_modified date/timestamp
                # row[1] is files_id
                # row[4] is md5
                #   if DB/last_modified is None update it with current
                #   file/last_modified value and do nothing else
                #
                #   if DB/lastmodified is different from file/lastmodified
                #   then: if md5 has changed then perform replacePhoto
                #   operation on Flickr
                try:
                    if (row[6] is None):
                        # Update db the last_modified time of file

                        # Control for when running multiprocessing set locking
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== '
                                          'in.lock.acquire')
                            lock.acquire()
                            logging.warning('===Multiprocessing=== '
                                            'out.lock.acquire')

                        cur.execute('UPDATE files SET last_modified = ? '
                                    'WHERE files_id = ?', (last_modified,
                                                           row[1]))
                        con.commit()

                        # Control when running multiprocessing release locking
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== '
                                          'in.lock.release')
                            lock.release()
                            logging.warning('===Multiprocessing=== '
                                            'out.lock.release')
                    if (row[6] != last_modified):
                        # Update db both the new file/md5 and the
                        # last_modified time of file by by calling replacePhoto

                        fileMd5 = self.md5Checksum(file)
                        if (fileMd5 != str(row[4])):
                            self.replacePhoto(lock, file, row[1], row[4],
                                              fileMd5, last_modified,
                                              cur, con);
                except lite.Error as e:
                    print "A DB error occurred:", e.args[0]
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                        lock.release()
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')

        # Closing DB connection
        if con is not None:
            con.close()
        return success

    #--------------------------------------------------------------------------
    # replacePhoto
    #   Should be only called from uploadFile
    #
    #   lock            = parameter for multiprocessing control of access to DB
    #                     if args.processes = 0 then lock can be None/not used
    #   file            = file to be uploaded to replace existing file
    #   file_id         = ID of the photo being replaced
    #   oldfileMd5      = Old file MD5 (required to update checksum tag
    #                     on Flikr)
    #   fileMd5         = New file MD5
    #   last_modified   = date/time last modification of the file to update
    #                     database
    #   cur             = current cursor for updating Database
    #   con             = current DB connection
    #
    def replacePhoto(self, lock, file, file_id,
                     oldFileMd5, fileMd5, last_modified, cur, con):
        """ replacePhoto
        lock            = parameter for multiprocessing control of access to DB
                          if args.processes = 0 then lock can be None/not used
        file            = file to be uploaded to replace existing file
        file_id         = ID of the photo being replaced
        oldfileMd5      = Old file MD5 (required to update checksum tag
                          on Flikr)
        fileMd5         = New file MD5
        last_modified   = date/time last modification of the file to update
                          database
        cur             = current cursor for updating Database
        con             = current DB connection
        """

        global nuflickr

        if args.dry_run:
            print(u'Dry Run Replace file ' + file.encode('utf-8') + u'...') \
                  if isThisStringUnicode(file) \
                  else ("Dry Run Replace file " + file + "...")
            return True

        success = False
        niceprint(u'Replacing the file: ' + file.encode('utf-8') + u'...') \
                  if isThisStringUnicode(file) \
                  else ("Replacing the file: " + file + "...")

        try:
            if isThisStringUnicode(file):
                photo = ('photo',
                         file.encode('utf-8'),
                         open(file, 'rb').read())
            else:
                photo = ('photo', file, open(file, 'rb').read())

            res = None
            res_add_tag = None
            res_get_info = None

            for x in range(0, MAX_UPLOAD_ATTEMPTS):
                try:
                    if (x > 0):
                        niceprint(u'Re-replacing ' +
                                  file.encode('utf-8') +
                                  u'...') \
                                  if isThisStringUnicode(file) \
                                  else ('Re-replacing ' + file + '...')
                    replaceResp = nuflickr.replace(
                                    filename=file,
                                    fileobj=FileWithCallback(file, callback),
                                    photo_id=file_id
                                )
                    logging.info('replaceResp: ')
                    logging.info(xml.etree.ElementTree.tostring(
                                                    replaceResp,
                                                    encoding='utf-8',
                                                    method='xml'))

                    if (self.isGood(replaceResp)):
                        # Update checksum tag at this time.
                        res_add_tag = flick.photos_add_tags(
                                        file_id,
                                        ['checksum:{}'.format(fileMd5)]
                                      )
                        logging.info('res_add_tag: ')
                        logging.info(xml.etree.ElementTree.tostring(
                                                res_add_tag,
                                                encoding='utf-8',
                                                method='xml'))
                        if (self.isGood(res_add_tag)):
                            # Gets Flickr file info to obtain all tags
                            # in order to update checksum tag if exists
                            res_get_info = flick.photos_get_info(
                                                photo_id=file_id
                                                )
                            logging.info('res_get_info: ')
                            logging.info(xml.etree.ElementTree.tostring(
                                                    res_get_info,
                                                    encoding='utf-8',
                                                    method='xml'))
                            # find tag checksum with oldFileMd5
                            # later use such tag_id to delete it
                            if (self.isGood(res_get_info)):
                                tag_id = None
                                for tag in res_get_info.\
                                                find('photo').\
                                                find('tags').\
                                                findall('tag'):
                                    if (tag.attrib['raw'] ==
                                           'checksum:{}'.format(oldFileMd5)):
                                        tag_id = tag.attrib['id']
                                        logging.info('Found tag_id:[{!s}]'
                                                     .format(tag_id))
                                        break
                                if not tag_id:
                                    niceprint('Can\'t find tag [{!s}]'
                                              'for file [{!s}]'
                                              .format(tag_id, file_id))
                                    # break from attempting to update tag_id
                                    break
                                else:
                                    # update tag_id with new Md5
                                    logging.info('Will remove tag_id:[{!s}]'
                                                 .format(tag_id))
                                    remtagResp = self.photos_remove_tag(tag_id)
                                    logging.info('remtagResp: ')
                                    logging.info(xml.etree.ElementTree
                                                 .tostring(remtagResp,
                                                           encoding='utf-8',
                                                           method='xml'))
                                    if (self.isGood(remtagResp)):
                                        niceprint('Tag removed.')
                                    else:
                                        niceprint('Tag Not removed.')

                    break
                # Exceptions for flickr.upload function call...
                except (IOError, ValueError, httplib.HTTPException):
                    niceprint('+++ #03 Caught IOError, ValueError, '
                              ' HTTP expcetion')
                    niceprint('Sleep 10 and try to replace again.')
                    niceprint(str(sys.exc_info()))
                    nutime.sleep(10)

                    if x == MAX_UPLOAD_ATTEMPTS - 1:
                        raise ValueError('Reached maximum number of attempts '
                                         'to replace, skipping')
                    continue

            if (not self.isGood(replaceResp)) or \
                   (not self.isGood(res_add_tag)) or \
                   (not self.isGood(res_get_info)):
                niceprint(u'A problem occurred while attempting to '
                          'replace the file: ' + file.encode('utf-8')) \
                          if isThisStringUnicode(file) \
                          else ('A problem occurred while attempting to '
                                'replace the file: ' + file)

            if (not self.isGood(replaceResp)):
                raise IOError(replaceResp)

            if (not(self.isGood(res_add_tag))):
                raise IOError(res_add_tag)

            if (not self.isGood(res_get_info)):
                raise IOError(res_get_info)

            niceprint(u'Successfully replaced the file: ' +
                      file.encode('utf-8')) \
                      if isThisStringUnicode(file) \
                      else ("Successfully replaced the file: " + file)

            # Update the db the file uploaded
            # Control for when running multiprocessing set locking
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== in.lock.acquire')
                lock.acquire()
                logging.warning('===Multiprocessing=== '
                                'out.lock.acquire')

            cur.execute('UPDATE files SET md5 = ?,last_modified = ? '
                        'WHERE files_id = ?',
                        (fileMd5, last_modified, file_id))
            con.commit()

            # Control for when running multiprocessing release locking
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== in.lock.release')
                lock.release()
                logging.warning('===Multiprocessing=== '
                                'out.lock.release')

            # Update Date/Time on Flickr for Video files
            # CODING: mimetypes already imported is it required?
            # import mimetypes
            filetype = mimetypes.guess_type(file)
            logging.info('filetype:[{!s}]:'.format(filetype[0])) \
                        if not (filetype[0] is None) \
                        else ('filetype is None!!!')

            if (not filetype[0] is None) and ('video' in filetype[0]):
                video_date = nutime.strftime('%Y-%m-%d %H:%M:%S',
                                             nutime.localtime(last_modified))
                logging.info('video_date:[{!s}]'.format(video_date))

                try:
                    res_set_date = flick.photos_set_dates(file_id, video_date)
                    if self.isGood(res_set_date):
                        niceprint("Set date ok")
                        niceprint(u'Successfully set date for pic: ' +
                                  file.encode('utf-8') +
                                  u' date:' +
                                  video_date.encode('utf-8')) \
                                  if isThisStringUnicode(file) \
                                  else ('Successfully set date for pic '
                                        'number: ' +
                                        file +
                                        ' date:' +
                                        video_date)
                except (IOError, ValueError, httplib.HTTPException):
                    print(str(sys.exc_info()))
                    print("Error setting date")

                if not self.isGood(res_set_date):
                    raise IOError(res_set_date)

                logging.debug()
                niceprint(u'Successfully set date for pic number: ' +
                          file.encode('utf-8') + u' date:' + video_date) \
                          if isThisStringUnicode(file) \
                          else ('Successfully set date for pic '
                                'number: ' +
                                file +
                                ' date:' +
                                video_date)

            success = True
        # CODING: Do I need this generic except?
        #         Maybe after flickr and SQLite3(lite) excepts?
        # except:
        #     print(str(sys.exc_info()))
        except flickrapi.exceptions.FlickrError as ex:
            niceprint('+++ #04 Caught flickrapi exception')
            niceprint('Error code: [{!s}]'.format(ex.code))
            niceprint('Error code: [{!s}]'.format(ex))
            niceprint(str(sys.exc_info()))
        except lite.Error as e:
            print "A DB error occurred:", e.args[0]
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== lock.release (in Error)')
                lock.release()
                logging.debug('===Multiprocessing=== lock.release (in Error)')
            success = False

        return success

    #--------------------------------------------------------------------------
    # deletefile
    #
    # When EXCLUDED_FOLDERS defintion changes. You can run the -g
    # or --remove-ignored option in order to remove files previously loaded
    # files from
    #
    def deleteFile(self, file, cur):
        """ deleteFile
        delete file from flickr
        cur represents the control dabase cursor to allow, for example,
            deleting empty sets
        """

        global nuflickr

        if args.dry_run:
            print(u'Deleting file: ' + file[1].encode('utf-8')) \
                  if isThisStringUnicode(file[1]) \
                  else ("Deleting file: " + file[1])
            return True

        success = False
        niceprint('Deleting file: ' + file[1].encode('utf-8')) \
                  if isThisStringUnicode(file[1]) \
                  else ('Deleting file: ' + file[1])
        try:
            deleteResp = nuflickr.photos.delete(
                                        photo_id=str(file[0]))
            logging.info('Output for {!s}:'.format('deleteResp'))
            logging.info(xml.etree.ElementTree.tostring(
                                    deleteResp,
                                    encoding='utf-8',
                                    method='xml'))
            if (self.isGood(deleteResp)):
                # Find out if the file is the last item in a set, if so,
                # remove the set from the local db
                cur.execute("SELECT set_id FROM files WHERE files_id = ?",
                            (file[0],))
                row = cur.fetchone()
                cur.execute("SELECT set_id FROM files WHERE set_id = ?",
                            (row[0],))
                rows = cur.fetchall()
                if (len(rows) == 1):
                    niceprint('File is the last of the set, '
                              'deleting the set ID: ' + str(row[0]))
                    cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))

                # Delete file record from the local db
                cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],))
                niceprint("Successful deletion.")
                success = True
            else:
                if (res['code'] == 1):
                    # File already removed from Flicker
                    cur.execute("DELETE FROM files WHERE files_id = ?",
                                (file[0],))
                else:
                    self.reportError(res)
        except:
            # If you get 'attempt to write a readonly database', set 'admin'
            # as owner of the DB file (fickerdb) and 'users' as group
            print(str(sys.exc_info()))
        return success

    #--------------------------------------------------------------------------
    # logSetCreation
    #
    #   Creates on flickrdb local database a SetName(Album)
    #
    def logSetCreation(self, setId, setName, primaryPhotoId, cur, con):
        """
        Creates on flickrdb local database a SetName(Album)
        """

        logging.info('setName:[{!s}] setName.type:[{!s}]'
                     .format(setName, type(setName)))
        logging.warning('Adding set: [{!s}] to database log.'.format(setName))
        if (args.verbose):
            niceprint('Adding set: [{!s}] to database log.'.format(setName))
        success = False

        cur.execute('INSERT INTO sets (set_id, name, primary_photo_id) '
                    'VALUES (?,?,?)',
                    (setId, setName, primaryPhotoId))
        cur.execute('UPDATE files SET set_id = ? WHERE files_id = ?',
                    (setId, primaryPhotoId))
        con.commit()
        return True

    #--------------------------------------------------------------------------
    # isGood
    #
    def isGood(self, res):
        """ isGood

            Returns true if attrib['stat'] == "ok" for a given XML object
        """
        if (res is None):
            return False
        elif (not res == "" and res.attrib['stat'] == "ok"):
            return True
        else:
            return False

    #--------------------------------------------------------------------------
    # reportError
    #
    def reportError(self, res):
        """ reportError
        """

        try:
            print("ReportError: " + str(res['code'] + " " + res['message']))
        except:
            print("ReportError: " + str(res))

    #--------------------------------------------------------------------------
    # run
    #
    # run in daemon mode. runs upload every SLEEP_TIME
    #
    def run(self):
        """ run
            Run in daemon mode. runs upload every SLEEP_TIME seconds.
        """

        logging.warning('Running in Daemon mode.')
        while (True):
            niceprint('Running in Daemon mode. Execute at [{!s}].'
                      .format(nutime.strftime(UPLDRConstants.TimeFormat)))
            # run upload
            self.upload()
            niceprint("Last check: " + str(nutime.asctime(time.localtime())))
            logging.warning('Running in Daemon mode. Sleep [{!s}] seconds.'
                            .format(SLEEP_TIME))
            nutime.sleep(SLEEP_TIME)

    #--------------------------------------------------------------------------
    # createSets
    #
    def createSets(self):
        """
            Creates a set (Album) in Flickr
        """
        niceprint('*****Creating Sets*****')

        if args.dry_run:
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path, set_id FROM files")

            files = cur.fetchall()

            for row in files:
                if FULL_SET_NAME:
                    # row[1] = path for the file from table files
                    setName = os.path.relpath(os.path.dirname(row[1]),
                                              unicode(FILES_DIR, 'utf-8'))
                else:
                    # row[1] = path for the file from table files
                    head, setName = os.path.split(os.path.dirname(row[1]))

                newSetCreated = False

                # Search local DB for set_id by setName(folder name )
                cur.execute("SELECT set_id, name FROM sets WHERE name = ?",
                            (setName,))
                set = cur.fetchone()

                if set is None:
                    # row[0] = files_id from files table
                    setId = self.createSet(setName, row[0], cur, con)
                    niceprint(u'Created the set: ' + setName.encode('utf-8')) \
                              if isThisStringUnicode(setName) \
                              else ('Created the set: ' + setName)
                    newSetCreated = True
                else:
                    # set[0] = set_id from sets table
                    setId = set[0]

                logging.debug('Creating Sets newSetCreated:[{!s}]'
                              'setId=[{!s}]'.format(newSetCreated, setId))

                # row[1] = path for the file from table files
                # row[2] = set_id from files table
                if row[2] is None and newSetCreated is False:
                    niceprint(u'adding file to set ' +
                              row[1].encode('utf-8') + u'...') \
                              if isThisStringUnicode(row[1]) \
                              else ("adding file to set " + row[1])

                    self.addFileToSet(setId, row, cur)

        # Closing DB connection
        if con is not None:
            con.close()
        niceprint('*****Completed creating sets*****')

    #--------------------------------------------------------------------------
    # addFiletoSet
    #
    def addFileToSet(self, setId, file, cur):
        """
            adds a file to set...
        """

        global nuflickr

        if args.dry_run:
                return True

        try:
            con = lite.connect(DB_PATH)
            con.text_factory = str

            logging.info('Calling nuflickr.photosets.addPhoto'
                         'set_id=[{!s}] photo_id=[{!s}]'
                         .format(setId, file[0]))
            # CODING Result for Error 3 is passed via exception
            addPhotoResp = nuflickr.photosets.addPhoto(
                                photoset_id=str(setId),
                                photo_id=str(file[0]))

            logging.info('addPhotoResp: ')
            logging.info(xml.etree.ElementTree.tostring(
                                                addPhotoResp,
                                                encoding='utf-8',
                                                method='xml'))

            if (self.isGood(addPhotoResp)):
                niceprint(u'Successfully added file ' +
                          file[1].encode('utf-8') +
                          u' to its set.') \
                          if isThisStringUnicode(file[1]) \
                          else ("Successfully added file " +
                                file[1] +
                                " to its set.")

                cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?",
                            (setId, file[0]))
                con.commit()

            else:
                if (addPhotoResp['code'] == 1):
                    niceprint('Photoset not found, creating new set...')
                    if FULL_SET_NAME:
                        setName = os.path.relpath(os.path.dirname(file[1]),
                                                  unicode(FILES_DIR, 'utf-8'))
                    else:
                        head, setName = os.path.split(os.path.dirname(file[1]))

                    self.createSet(setName, file[0], cur, con)
                elif (addPhotoResp['code'] == 3):
                    niceprint('Photo already in set... updating DB')
                    niceprint(addPhotoResp['message'] + '... updating DB')
                    cur.execute('UPDATE files SET set_id = ? '
                                'WHERE files_id = ?', (setId, file[0]))
                else:
                    self.reportError(res)
            # CODING: Not originally here
            # Closing DB connection
            # if con is not None:
            #     con.close()
        except flickrapi.exceptions.FlickrError as ex:
            niceprint('+++ #05 Caught flickrapi exception')
            # Error: 3: Photo Already in set
            if (ex.code == 3):
                try:
                    niceprint('Photo already in set... updating DB'
                              'set_id=[{!s}] photo_id=[{!s}]'
                              .format(setId, file[0]))
                    cur.execute('UPDATE files SET set_id = ? '
                                'WHERE files_id = ?', (setId, file[0]))
                    con.commit()
                except lite.Error, e:
                    print("+++ #05 A DB error occurred: %s" % e.args[0])
            else:
                niceprint('Error code: [{!s}]'.format(ex.code))
                niceprint('Error code: [{!s}]'.format(ex))
                niceprint(str(sys.exc_info()))
        except lite.Error, e:
            print("A DB error occurred: %s" % e.args[0])
        except:
            niceprint('+++ #06 Caught an exception')
            print(str(sys.exc_info()))

    #--------------------------------------------------------------------------
    # createSet
    #
    def createSet(self, setName, primaryPhotoId, cur, con):
        """

        """

        global nuflickr

        logging.debug(u'Creating new set: '.encode('utf-8') + str(setName))
        niceprint(u'Creating new set: '.encode('utf-8') + str(setName))

        if args.dry_run:
            return True

        try:
            createResp = nuflickr.photosets.create(
                            title=setName,
                            primary_photo_id=str(primaryPhotoId))
            logging.warning('createResp: ')
            logging.warning(xml.etree.ElementTree.tostring(createResp,
                                                           encoding='utf-8',
                                                           method='xml'))

            if (self.isGood(createResp)):
                logging.warning('createResp["photoset"]["id"]:[{!s}]'
                                .format(createResp.find('photoset')
                                        .attrib['id']))
                self.logSetCreation(createResp.find('photoset').attrib['id'],
                                    setName,
                                    primaryPhotoId,
                                    cur,
                                    con)
                return createResp.find('photoset').attrib['id']
            else:
                logging.warning('createResp: ')
                logging.warning(xml.etree.ElementTree.tostring(
                                                    createResp,
                                                    encoding='utf-8',
                                                    method='xml'))
                self.reportError(createResp)
        except:
            print(str(sys.exc_info()))
        return False

    #--------------------------------------------------------------------------
    # setupDB
    #
    # Creates the control database
    #
    def setupDB(self):
        """
            setupDB

            Creates the control database
        """
        niceprint('Setting up the database: ' + DB_PATH)
        con = None
        try:
            con = lite.connect(DB_PATH)
            con.text_factory = str
            cur = con.cursor()
            cur.execute('CREATE TABLE IF NOT EXISTS files '
                        '(files_id INT, path TEXT, set_id INT, '
                        'md5 TEXT, tagged INT)')
            cur.execute('CREATE TABLE IF NOT EXISTS sets '
                        '(set_id INT, name TEXT, primary_photo_id INTEGER)')
            cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS fileindex '
                        'ON files (path)')
            cur.execute('CREATE INDEX IF NOT EXISTS setsindex ON sets (name)')
            con.commit()

            # Check database version.
            # [0] = newly created
            # [1] = with last_modified column
            # [2] = badfiles table added
            cur = con.cursor()
            cur.execute('PRAGMA user_version'); row = cur.fetchone()
            if (row[0] == 0):
                # Database version 1
                niceprint('Adding last_modified column to database')
                cur = con.cursor()
                cur.execute('PRAGMA user_version="1"')
                cur.execute('ALTER TABLE files ADD COLUMN last_modified REAL')
                con.commit()
                # obtain new version to continue updating database
                cur = con.cursor()
                cur.execute('PRAGMA user_version'); row = cur.fetchone()
            if (row[0] == 1):
                # Database version 2
                # Cater for badfiles
                niceprint('Adding table badfiles to database')
                cur.execute('PRAGMA user_version="2"')
                cur.execute('CREATE TABLE IF NOT EXISTS badfiles '
                            '(files_id INTEGER PRIMARY KEY AUTOINCREMENT, '
                            'path TEXT, set_id INT, md5 TEXT, tagged INT, '
                            'last_modified REAL)')
                cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS badfileindex '
                            'ON badfiles (path)')
                con.commit();
                cur = con.cursor()
                cur.execute('PRAGMA user_version'); row = cur.fetchone()
            if (row[0] == 2):
                niceprint('Database version: [{!s}]'.format(row[0]))
                # Database version 3
                # ...for future use!
            # Closing DB connection
            if con is not None:
                con.close()
        except lite.Error, e:
            niceprint("setup DB Error: %s" % e.args[0])
            if con is not None:
                con.close()
            sys.exit(1)
        finally:
            niceprint('Completed database setup')

    #--------------------------------------------------------------------------
    # cleanDBbadfiles
    #
    # Cleans up (deletes) contents from DB badfiles table
    #
    def cleanDBbadfiles(self):
        """
            cleanDBbadfiles

            Cleans up (deletes) contents from DB badfiles table
        """
        niceprint('Cleaning up badfiles table from the database: ' + DB_PATH)
        con = None
        try:
            con = lite.connect(DB_PATH)
            con.text_factory = str
            cur = con.cursor()
            cur.execute('PRAGMA user_version')
            row = cur.fetchone()
            if (row[0] >= 2):
                # delete from badfiles table and reset SEQUENCE
                niceprint('Deleting from badfiles table. Reseting sequence.')
                cur.execute('DELETE FROM badfiles')
                cur.execute('DELETE FROM SQLITE_SEQUENCE '
                            'WHERE name="badfiles"')
                con.commit()
            else:
                niceprint('Wrong DB version. '
                          'Expected 2 or higher and not:[{!s}]'.format(row[0]))
            # Closing DB connection
            if con is not None:
                con.close()
        except lite.Error, e:
            niceprint("Error: %s" % e.args[0])
            if con is not None:
                con.close()
            sys.exit(1)
        finally:
            niceprint('Completed cleaning up badfiles table from the database')

    #--------------------------------------------------------------------------
    # md5Checksum
    #
    def md5Checksum(self, filePath):
        """
            Calculates the MD5 checksum for filePath
        """
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    # -------------------------------------------------------------------------
    # Method to clean unused sets
    #   Sets are Albums.
    def removeUselessSetsTable(self):
        niceprint('*****Removing empty Sets from DB*****')
        if args.dry_run:
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT set_id, name FROM sets WHERE set_id NOT IN\
                        (SELECT set_id FROM files)")
            unusedsets = cur.fetchall()

            for row in unusedsets:
                niceprint('Removing set [' +
                          str(row[0]) +
                          "] (" +
                          row[1].decode('utf-8') +
                          ').')

                cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))
            con.commit()

        # Closing DB connection
        if con is not None:
            con.close()
        niceprint('*****Completed removing empty Sets from DB*****')

    # -------------------------------------------------------------------------
    # Display Sets
    #
    def displaySets(self):
        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT set_id, name FROM sets")
            allsets = cur.fetchall()
            for row in allsets:
                print("Set: " + str(row[0]) + "(" + row[1] + ")")
        # Closing DB connection
        if con is not None:
            con.close()

    #--------------------------------------------------------------------------
    # Get sets from Flickr
    #
    # Selects the flickrSets from Flickr
    # for each flickrSet
    #   Searches localDBSet from local database (flickrdb)
    #   if localDBSet is None then INSERTs flickrset into flickrdb
    #
    def getFlickrSets(self):
        """
            getFlickrSets

            Gets list of FLickr Sets (Albums) and populates
            local DB accordingly
        """
        global nuflickr

        niceprint('*****Adding Flickr Sets to DB*****')
        if args.dry_run:
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        try:
            sets = nuflickr.photosets_getList()

            logging.debug('Output for {!s}'.format('photosets_getList:'))
            logging.debug(xml.etree.ElementTree.tostring(sets,
                                                         encoding='utf-8',
                                                         method='xml'))

            """

sets = flickr.photosets.getList(user_id='73509078@N00')

sets.attrib['stat'] => 'ok'
sets.find('photosets').attrib['cancreate'] => '1'

set0 = sets.find('photosets').findall('photoset')[0]

+-------------------------------+-----------+
| variable                      | value     |
+-------------------------------+-----------+
| set0.attrib['id']             | u'5'      |
| set0.attrib['primary']        | u'2483'   |
| set0.attrib['secret']         | u'abcdef' |
| set0.attrib['server']         | u'8'      |
| set0.attrib['photos']         | u'4'      |
| set0.title[0].text            | u'Test'   |
| set0.description[0].text      | u'foo'    |
| set0.find('title').text       | 'Test'    |
| set0.find('description').text | 'foo'     |
+-------------------------------+-----------+

... and similar for set1 ...

            """

            if (self.isGood(sets)):
                cur = con.cursor()

                for row in sets.find('photosets').findall('photoset'):
                    logging.info('Output for {!s}:'.format('row'))
                    logging.info(xml.etree.ElementTree.tostring(
                                                        row,
                                                        encoding='utf-8',
                                                        method='xml'))

                    setId = row.attrib['id']
                    setName = row.find('title').text
                    primaryPhotoId = row.attrib['primary']

                    logging.debug('isThisStringUnicode [{!s}]:{!s}'
                                  .format('setId',
                                          isThisStringUnicode(setId)))
                    logging.debug('isThisStringUnicode [{!s}]:{!s}'
                                  .format('setName',
                                          isThisStringUnicode(setName)))
                    logging.debug('isThisStringUnicode [{!s}]:{!s}'
                                  .format('primaryPhotoId',
                                          isThisStringUnicode(primaryPhotoId)))

                    if (args.verbose):
                        niceprint(u'id=['.encode('utf-8') +
                                  setId.encode('utf-8') +
                                  u'] '.encode('utf-8') +
                                  u'setName=['.encode('utf-8') +
                                  setName if setName is not None else 'None' +
                                  u'] '.encode('utf-8') +
                                  u'primaryPhotoId=['.encode('utf-8') +
                                  primaryPhotoId.encode('utf-8') +
                                  u']'.encode('utf-8'))

                    # Control for when flickr return a setName (title) as None
                    # Occurred while simultaneously performing massive delete
                    # operation on flickr.
                    if setName is not None:
                        logging.info('Searching on DB for setId:[{!s}] '
                                     'setName:[{!s}] '
                                     'primaryPhotoId:[{!s}]'
                                     .format(setId,
                                             setName.encode('utf-8'),
                                             primaryPhotoId))
                    else:
                        logging.info('Searching on DB for setId:[{!s}] '
                                     'setName:[None] '
                                     'primaryPhotoId:[{!s}]'
                                     .format(setId,
                                             primaryPhotoId))

                    logging.info("SELECT set_id FROM sets WHERE set_id = '" +
                                 setId + "'")
                    cur.execute("SELECT set_id FROM sets WHERE set_id = '" +
                                setId + "'")
                    foundSets = cur.fetchone()
                    logging.info('Output for foundSets is [None]:') \
                        if (foundSets is None) \
                        else logging.info('Output for foundSets is [{!s}]:'
                                          .format(foundSets))

                    if (foundSets is None):
                        niceprint(u'Adding set ['.encode('utf-8') +
                                  setId.encode('utf-8') +
                                  u'] ('.encode('utf-8') +
                                  setName if setName is not None else 'None' +
                                  u') '.encode('utf-8') +
                                  u'with primary photo '.encode('utf-8') +
                                  primaryPhotoId.encode('utf-8') +
                                  u'.'.encode('utf-8'))

                        cur.execute('INSERT INTO sets (set_id, name, '
                                    'primary_photo_id) VALUES (?,?,?)',
                                    (setId, setName, primaryPhotoId))
                    else:
                        logging.info('Flickr Set/Album already on '
                                     'local database.')
                        if (args.verbose):
                            niceprint('Flickr Set/Album already on '
                                      'local database.')

                con.commit()
                # niceprint('Sleep...3...to allow Commit... TO BE REMOVED?')
                # nutime.sleep(3)
                # niceprint('After Sleep...3...to allow Commit')
                # Closing DB connection
                if con is not None:
                    con.close()
            else:
                logging.warning(xml.etree.ElementTree.tostring(
                                    sets,
                                    encoding='utf-8',
                                    method='xml'))
                self.reportError(sets)

        except flickrapi.exceptions.FlickrError as ex:
            print("Error code: %s" % ex.code)
            print("Error code:", ex)
            print(str(sys.exc_info()))

        # except:
        #     print "EXCEPTION"
        #     FlickrError
        #     print(str(sys.exc_info()))

        # Closing DB connection
        if con is not None:
            con.close()
        niceprint('*****Completed adding Flickr Sets to DB*****')

    #--------------------------------------------------------------------------
    # photos_search
    #
    # Searchs for image with on tag:checksum (calls Flickr photos.search)
    #
    # Will return searchResp and if isgood(searchResp) will provide also
    # searchtotal and id of first photo
    
    # Sample response:
    # <photos page="2" pages="89" perpage="10" total="881">
    #     <photo id="2636" owner="47058503995@N01" 
    #             secret="a123456" server="2" title="test_04"
    #             ispublic="1" isfriend="0" isfamily="0" />
    #     <photo id="2635" owner="47058503995@N01"
    #         secret="b123456" server="2" title="test_03"
    #         ispublic="0" isfriend="1" isfamily="1" />
    # </photos>
    def photos_searchDELETE(self, checksum):
        """
            photos_search
            Searchs for image with on tag:checksum
        """

        global nuflickr

        logging.info('checksum:{!s}:'.format(checksum))

        # CODGIN EXTREME
            
        globalcounter = 0
        curcounter = 0
        for pg in range(180):
        
            print ('page=[{!s}]'.format(pg))
            searchResp = nuflickr.photos.search(user_id="me",per_page=250)
            if not (self.isGood(searchResp)):
                break
            niceprint(xml.etree.ElementTree.tostring(
                                searchResp,
                                encoding='utf-8',
                                method='xml'))

            list = searchResp.find('photos').findall('photo')

            if searchResp.find('photos').attrib['total'] == 0:
                print ('returned total of pics = 0. Break')
                break
            else:
                curcounter = 0
                foundpics = searchResp.find('photos').attrib['total']
                print ('total of pics = [{!s}]'
                       .format(foundpics))
    
            if len(list) == 0:
                print ('list is empty. Break')
                break

            for i, a in enumerate(list):
                print (a.attrib['id'])
                try:
                    deleteResp = nuflickr.photos.delete(photo_id=str(a.attrib['id']))
                    niceprint('DELETE_result:[{!s}]'.format(self.isGood(deleteResp)))
                except:
                    niceprint('+++ #99 Caught an exception')
                    print(str(sys.exc_info()))
                globalcounter += 1
                curcounter += 1
                print('next file:[{!s}] Total so far:[{!s}]. '
                      'Current [{!s}] of [{!s}]'
                      .format(i, globalcounter, curcounter, foundpics))
                sys.stdout.flush()
                
            print('next page:[{!s}]'.format(pg))
                
            # logging.info('Output for {!s}:'.format('deleteResp'))
            # logging.info(xml.etree.ElementTree.tostring(
            #                         deleteResp,
            #                         encoding='utf-8',
            #                         method='xml'))

        # searchResp = nuflickr.photos.search(tags='checksum:{}'
        #                                     .format(checksum))
        

        # Debug
        # logging.debug('Search Results SearchResp:')
        # logging.debug(xml.etree.ElementTree.tostring(
        #                                     searchResp,
        #                                     encoding='utf-8',
        #                                     method='xml'))

        tot = None
        id = None
        if self.isGood(searchResp):
            if int(searchResp.find('photos').attrib['total']) == 0:
                tot = int(searchResp.find('photos').attrib['total'])
                if int(searchResp.find('photos').attrib['total']) == 1:
                    id = searchResp.find('photos').findall('photo')[0].attrib['id']

        return (searchResp, tot, id)

    #--------------------------------------------------------------------------
    # people_get_photos
    #
    #   Local Wrapper for Flickr people.getPhotos
    #
    def people_get_photos(self):
        """
        """

        global nuflickr

        getPhotosResp = nuflickr.people.getPhotos(user_id="me",
                                                  per_page=1)
        return getPhotosResp

    #--------------------------------------------------------------------------
    # photos_get_not_in_set
    #
    #   Local Wrapper for Flickr photos.getNotInSet
    #
    def photos_get_not_in_set(self, per_page):
        """
        Local Wrapper for Flickr photos.getNotInSet
        """

        global nuflickr

        notinsetResp = nuflickr.photos.getNotInSet(per_page=per_page)

        return notinsetResp

    #--------------------------------------------------------------------------
    # photos_add_tags
    #
    #   Local Wrapper for Flickr photos.addTags
    #
    def photos_add_tags(self, photo_id, tags):
        """
        Local Wrapper for Flickr photos.addTags
        """

        global nuflickr

        photos_add_tagsResp = nuflickr.photos.addTags(photo_id=photo_id,
                                                      tags=tags)
        return photos_add_tagsResp

    #--------------------------------------------------------------------------
    # photos_get_info
    #
    #   Local Wrapper for Flickr photos.getInfo
    #
    def photos_get_info(self, photo_id):
        """
        Local Wrapper for Flickr photos.getInfo
        """

        global nuflickr

        photos_get_infoResp = nuflickr.photos.getInfo(photo_id=photo_id)

        return photos_get_infoResp

    #--------------------------------------------------------------------------
    # photos_remove_tag
    #
    #   Local Wrapper for Flickr photos.removeTag
    #   The tag to remove from the photo. This parameter should contain
    #   a tag id, as returned by flickr.photos.getInfo.
    #
    def photos_remove_tag(self, tag_id):
        """
        Local Wrapper for Flickr photos.removeTag

        The tag to remove from the photo. This parameter should contain
        a tag id, as returned by flickr.photos.getInfo.
        """

        global nuflickr

        removeTagResp = nuflickr.photos.removeTag(tag_id=tag_id)

        return removeTagResp

    #--------------------------------------------------------------------------
    # photos_set_dates
    #
    # Update Date/Time Taken on Flickr for Video files
    #
    def photos_set_dates(self, photo_id, datetxt):
        """
        Update Date/Time Taken on Flickr for Video files
        """
        global nuflickr

        respDate = nuflickr.photos.setdates(photo_id=photo_id,
                                            date_taken=datetxt)
        logging.info('Output for {!s}:'.format('respDate'))
        logging.info(xml.etree.ElementTree.tostring(
                                respDate,
                                encoding='utf-8',
                                method='xml'))

        return respDate

    #--------------------------------------------------------------------------
    # print_stat
    #
    # List Local pics, loaded pics into Flickr, pics not in sets on Flickr
    #
    def print_stat(self):
        """ print_stat
        Shows Total photos and Photos Not in Sets on Flickr
        """
        # Total Local photos count
        con = lite.connect(DB_PATH)
        con.text_factory = str
        countlocal = 0
        with con:
            cur = con.cursor()
            cur.execute("SELECT Count(*) FROM files")

            countlocal = cur.fetchone()[0]
            if LOGGING_LEVEL <= logging.DEBUG:
                print('Total photos on local: {}'.format(countlocal))

        # Total FLickr photos count:
        #       find('photos').attrib['total']
        countflickr = 0
        res = self.people_get_photos()
        if not self.isGood(res):
            raise IOError(res)
        logging.debug('Output for people_get_photos:')
        logging.debug(xml.etree.ElementTree.tostring(
                                res,
                                encoding='utf-8',
                                method='xml'))

        countflickr = format(res.find('photos').attrib['total'])
        logging.debug('Total photos on flickr: {!s}'.format(countflickr))

        # Total photos not on Sets/Albums on FLickr
        # (per_page=1 as only the header is required to obtain total):
        #       find('photos').attrib['total']
        res = self.photos_get_not_in_set(1)
        if not self.isGood(res):
            raise IOError(res)
        logging.debug('Output for get_not_in_set:')
        logging.debug(xml.etree.ElementTree.tostring(
                                res,
                                encoding='utf-8',
                                method='xml'))

        countnotinsets = 0
        countnotinsets = int(format(res.find('photos').attrib['total']))
        logging.debug('Photos not in sets on flickr: {!s}'
                      .format(countnotinsets))

        # Print total stats counters
        niceprint('Photos count: Local:[' + str(countlocal) + '] ' +
                  'Flickr:[' + str(countflickr) + '] ' +
                  'Not in sets on Flickr:[' + str(countnotinsets) + '] ')

        # List pics not in sets (if within a parameter)
        # Maximum allowed per_page by Flickr is 500.
        # Avoid going over in order not to have to handle multipl pages.
        if (args.list_photos_not_in_set and
                args.list_photos_not_in_set > 0 and
                countnotinsets > 0):
            niceprint('*****Listing Photos not in a set in Flickr******')
            # List pics not in sets (if within a parameter, default 10)
            # (per_page=min(args.list_photos_not_in_set, 500):
            #       find('photos').attrib['total']
            res = self.photos_get_not_in_set(
                                min(args.list_photos_not_in_set, 500))
            if not self.isGood(res):
                raise IOError(res)
            logging.debug('Output for list get_not_in_set:')
            logging.debug(xml.etree.ElementTree.tostring(
                                    res,
                                    encoding='utf-8',
                                    method='xml'))
            for count, row in enumerate(res.find('photos').findall('photo')):
                logging.debug(
                    u'Photo get_not_in_set '
                    u'id:[{!s}] '
                    u'title:[{!s}]'.format(row.attrib['id'],
                                           row.attrib['title']))
                logging.debug(xml.etree.ElementTree.tostring(
                                row,
                                encoding='utf-8',
                                method='xml'))
                niceprint(u'Photo get_not_in_set: id:[' +
                          row.attrib['id'] + u'] ' +
                          u'title:[' +
                          row.attrib['title'] + u']')
                logging.debug('count=[{!s}]'.format(count))
                if (count == 500) or \
                        (count >= (args.list_photos_not_in_set-1)) or \
                        (count >= (countnotinsets-1)):
                    logging.debug('Stopped at photo [{!s}] listing '
                                  'photos not in a set'.format(count))
                    break
            niceprint('*****Completed Listing Photos not in a set '
                      'in Flickr******')

#==============================================================================
# Main code
#
# nutime = time

niceprint('--------- (V' + UPLDRConstants.Version + ') Start time: ' +
          nutime.strftime(UPLDRConstants.TimeFormat) +
          ' ---------')
if __name__ == "__main__":
    # Ensure that only once instance of this script is running
    f = open(LOCK_PATH, 'w')
    try:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        if e.errno == errno.EAGAIN:
            sys.stderr.write('[{!s}] Script already running.\n'
                             .format(
                                nutime.strftime(UPLDRConstants.TimeFormat)))
            sys.exit(-1)
        raise
    parser = argparse.ArgumentParser(
                        description='Upload files to Flickr. '
                                    'Uses uploadr.ini as config file.'
                        )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Provides some more verbose output. '
                             'Will provide progress information on upload. '
                             'See also LOGGING_LEVEL value in INI file.')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Dry run')
    parser.add_argument('-i', '--title', action='store',
                        help='Title for uploaded files. '
                             'Overwrites title from INI config file. '
                             'If not indicated and not defined in INI file, '
                             'it uses filename as title.')
    parser.add_argument('-e', '--description', action='store',
                        help='Description for uploaded files'
                             'Overwrites description from INI config file. ')
    parser.add_argument('-t', '--tags', action='store',
                        help='Space-separated tags for uploaded files. '
                             'It appends to the tags defined in INI file.')
    parser.add_argument('-r', '--drip-feed', action='store_true',
                        help='Wait a bit between uploading individual files')
    parser.add_argument('-p', '--processes',
                        metavar='P', type=int,
                        help='Number of photos to upload simultaneously.')
    # when you change EXCLUDE_FOLDERS setting
    parser.add_argument('-g', '--remove-ignored', action='store_true',
                        help='Remove previously uploaded files, that are '
                             'now being ignored due to change of the INI '
                             'file configuration EXCLUDED_FOLDERS')
    # used in print_stat function
    parser.add_argument('-l', '--list-photos-not-in-set',
                        metavar='N', type=int,
                        help='List as many as N photos not in set. '
                             'Maximum listed photos is 500.')
    # run in daemon mode uploading every X seconds
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run forever as a daemon.'
                             'Uploading every SLEEP_TIME seconds'
                             'Please note it only performs upload/replace')
    # cater for bad files. files in your Library that flickr does not recognize
    # -b add files to badfiles table
    parser.add_argument('-b', '--bad-files', action='store_true',
                        help='Save on database bad files to prevent '
                             'continuous uploading attempts. Bad files are '
                             'files in your Library that flickr does not '
                             'recognize (Error 5). Check also option -c.')
    # cater for bad files. files in your Library that flickr does not recognize
    # -c clears the badfiles table to allow a reset of the list
    parser.add_argument('-c', '--clean-bad-files', action='store_true',
                        help='Resets the badfiles table/list to allow a new '
                             'uploading attempt for bad files. Bad files are '
                             'files in your Library that flickr does not '
                             'recognize (Error 5). Check also option -b. ')

    # parse arguments
    args = parser.parse_args()

    # Debug to show arguments
    if LOGGING_LEVEL <= logging.INFO:
        logging.info('Pretty Print Output for {!s}'.format('args:'))
        pprint.pprint(args)

    logging.warning('FILES_DIR: [{!s}]'.format(FILES_DIR))
    if FILES_DIR == "":
        niceprint('Please configure the name of the folder [FILES_DIR] '
                  'in the INI file [normally uploadr.ini], '
                  'with media available to sync with Flickr.')
        sys.exit()
    else:
        if not os.path.isdir(FILES_DIR):
            niceprint('Please configure the name of an existant folder '
                      'in the INI file [normally uploadr.ini] '
                      'with media available to sync with Flickr.')
            sys.exit()

    if FLICKR["api_key"] == "" or FLICKR["secret"] == "":
        niceprint('Please enter an API key and secret in the configuration '
                  'script file, normaly uploadr.ini (see README).')
        sys.exit()

    # Instantiate class Uploadr
    logging.debug('Instantiating the Main class flick = Uploadr()')
    flick = Uploadr()

    # Setup the database
    flick.setupDB()
    if (args.clean_bad_files):
        flick.cleanDBbadfiles()

    niceprint("Checking if token is available... if not will authenticate")
    if not flick.checkToken():
        flick.authenticate()

    # CODING: EXTREME
    res, t, i = flick.photos_searchDELETE('f5feeae3541ecff04a7a145d9919b4c0')
    print('res=',res)
    print('t=',t)
    print('i=',i)
        
niceprint('--------- (V' + UPLDRConstants.Version + ') End time: ' +
          nutime.strftime(UPLDRConstants.TimeFormat) +
          ' ---------')
