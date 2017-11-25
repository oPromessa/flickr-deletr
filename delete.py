#!/usr/bin/env python

"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-deletr/

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
import sys
import argparse
import os
import time
import sqlite3 as lite
import hashlib
import fcntl
import errno
import ConfigParser
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
    Version = '1.0.0'

    def __init__(self):
        """ Constructor
        """
        pass

# ----------------------------------------------------------------------------
# Global Variables
#   nutime      = for working with time module (import time)
#   nuflickr    = object for flickr API module (import flickrapi)
nutime = time
nuflickr = None

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
            'deletr',
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
    sys.stderr.write('[{!s}]:[{!s}][WARNING ]:[deletr] ({!s}) TOKEN_CACHE '
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
    sys.stderr.write('[{!s}]:[WARNING ]:[deletr] LOGGING_LEVEL '
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

    #--------------------------------------------------------------------------
    # photos_searchDELETE
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

        # CODING EXTREME
            
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
    # run in daemon mode uploading every X seconds
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run forever as a daemon.'
                             'Uploading every SLEEP_TIME seconds'
                             'Please note it only performs upload/replace')

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
