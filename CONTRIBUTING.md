# flickr-uploader: CONTRIBUTING
* by oPromessa, 2017, V2.7.1
* Published on https://github.com/oPromessa/flickr-uploader/

## Contributing
* You're welcome to contribute!
* Feel free to let me know what you're working on for coordinating efforts.

## Programming Remarks
* Follow PEP8 coding guidelines. (see http://pep8online.com/checkresult)
* Temporary coding remarks within code marked with `CODING` keyword comment
* If using isThisStringUnicode for (something) if test else (other) make
  sure to break lines with \ correctly. Be careful.
* Use niceprint function to output messages to stdout. Control verbosity. Use logalso for logging.
  ```python
  niceprint(' Always shows')
  niceprint(' Always shows', verbosity=0)
  niceprint(' Shows on mode verbose', verbosity=1)
  niceprint(' IS_UPLOADED:[ERROR#1]', fname='isuploaded', verbosity=2)
  niceprint(' IS_UPLOADED:[ERROR#1]', fname='isuploaded', verbosity=2, logalso=logging.ERROR)
  ```
* Use logging. for CRITICAL, ERROR, WARNING, INFO, DEBUG messages to stderr.
  Three uses and one remark:
   * Simply log message at approriate level
   ``python
   logging.warning('Status: {!s}'.format('Setup Complete'))
   ```
   * Control additional specific output to stderr depending on level
   ```python
   if LOGGING_LEVEL <= logging.INFO:
       logging.info('Output for [%s] is: %s',
                    'uploadResp',
                    xml.etree.ElementTree.tostring(uploadPhotoResp,
                                                   encoding='utf-8',
                                                   method='xml'))
       # <generate any further output>
   ```
   * Control additional specific output to stdout depending on level
   ```python
   if LOGGING_LEVEL <= logging.INFO:
       niceprint ('Output for {!s}:'.format('uploadResp'))
       xml.etree.ElementTree.dump(uploadResp)
       # <generate any further output>
   ```
   * Change logging level on the fly...
   ```python
   logging.getLogger().setLevel(logging.WARNING)
   logging.debug('Debug messge not shown!')
   logging.getLogger().setLevel(logging.DEBUG)
   logging.debug('Debug messge shown!')
   ```
* Specific CODING related comments are marked with `CODING keyword
* Prefix coding for some output messages:
   * `*****`   Section informative
   * `===`     Multiprocessing related
   * `___`     Retry related (check retry function)
   * `+++`     Exceptions handling related
   * `+++ DB`  Database Exceptions handling related
   * `xxx`     Error related
* CODING Logging/Messaging groundrules:
   * niceprint
   * niceprint with verbose count=1
   * niceprint with verbose count=2, 3, ...
   * logging.critical: Blocking situations
   * logging.error: Relevant errors
   * Handled Exceptions: Messages controlled via reportError function
   * logging.warning: relevant conclusions/situations
   * logging.info: relevant output of variables
   * logging.debug: entering and exiting functions
   * Note: Consider using assertions: check niceassert function.
* Protect all DB access (single processing or multiprocessing) with:
    ```python
    try:
        # Acquire DB lock if running in multiprocessing mode
        self.useDBLock( lock, True)
        cur.execute('SELECT rowid,files_id,path,set_id,md5,tagged,'
                  'last_modified FROM files WHERE path = ?', (file,))
    except lite.Error as e:
        reportError(Caught=True,
            CaughtPrefix='+++ DB',
            CaughtCode='990',
            CaughtMsg='DB error on SELECT: [{!s}]'
                      .format(e.args[0]),
            NicePrint=True)
    finally:
        # Release DB lock if running in multiprocessing mode
        self.useDBLock( lock, False)
    ```
* As far as my testing goes :) the following errors are handled:
   * Flickr reports file not loaded due to error: `5 [flickr:Error:
   5: Filetype was not recognised]`
      * Such files are recorded so that they are not reloaded again.
      * Check -b and -c options.
   * Flickr reports file not loaded due to error: `8 [flickr:Error:
   8: Filesize was too large]`
      * Database is locked
      * error setting video date
      * error 502: flickrapi
      * error 504: flickrapi
* While testing with pytest --flakes Python 2 and 3 compatibility is
  achieved by avoiding warnings on lines that contain a `# noqa comment at
  the end will not issue warnings. Applicable on use of unicode for
  instance. Please note. `# noqa` must appear **as is** at the end of the
  line to be ignored.
    ```python
          FILES_DIR = unicode(  # noqa
                            '', 'utf-8') if sys.version_info < (3, ) else str('')
    ```
* Pypi test install:
  `pip2.7 install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple flickr-uploader --prefix=~/apps/Python`
  Use flickr-uploader==2.8.6a1 to install a specific version (alpha1 in this case)
* setup.py install: use --old-and-unmanageable option to copy data files.
  `python2.7 setup.py install --prefix=~/apps/Python --old-and-unmanageable`
