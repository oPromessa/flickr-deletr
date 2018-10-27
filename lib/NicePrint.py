"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-uploader/

    Helper class and functions to print messages.
"""

# -----------------------------------------------------------------------------
# Import section for Python 2 and 3 compatible code
# from __future__ import absolute_import, division, print_function,
#    unicode_literals
from __future__ import division    # This way: 3 / 2 == 1.5; 3 // 2 == 1

# -----------------------------------------------------------------------------
# Import section
#
import sys
import os
import logging
import time
import re
import hashlib
# -----------------------------------------------------------------------------
# Helper class and functions for UPLoaDeR Global Constants.
import lib.Konstants as KonstantsClass

# =============================================================================
# Functions aliases
#
#   UPLDR_K = KonstantsClass.Konstants
# -----------------------------------------------------------------------------
UPLDR_K = KonstantsClass.Konstants()


# -----------------------------------------------------------------------------
# class NicePrint to be used to print messages.
#
class NicePrint:
    """
        >>> import sys
        >>> import lib.NicePrint as npc
        >>> np = npc.NicePrint()
        >>> if sys.version_info < (3, ):
        ...     np.is_str_unicode('Something') == False
        ... else:
        ...     np.is_str_unicode('Something') == False
        True
        >>> if sys.version_info < (3, ):
        ...     np.is_str_unicode(u'With u prefix') == True
        ... else:
        ...     np.is_str_unicode(u'With u prefix') == False
        True
        >>> np.is_str_unicode(245)
        False
        >>> np.verbosity == 0
        True
        >>> np.set_verbosity(3)
        >>> np.get_verbosity()
        3
        >>> np.verbosity == 3
        True
    """

    # -------------------------------------------------------------------------
    # Class Global Variables
    #   class variable shared by all instances
    #
    #   verbosity = Verbosity Level defined: 0, 1, 2, ...
    #   masking   = Masking sensitive data: True/False

    verbosity = 0
    mask_sensitivity = False

    # -------------------------------------------------------------------------
    # class NicePrint __init__
    #
    def __init__(self, averbosity=0, amask_sensitivity=False):
        """ class NicePrint __init__

            verbosity = Verbosity Level defined: 0, 1, 2, ...
        """

        self.set_verbosity(averbosity)
        self.set_mask_sensitivity(amask_sensitivity)

    # -------------------------------------------------------------------------
    # set_verbosity
    #
    @classmethod
    def set_verbosity(cls, averbosity=0):
        """ set_verbosity

            verbosity = Verbosity Level defined: 0, 1, 2, ...
        """

        cls.verbosity = averbosity if averbosity is not None else 0

    # -------------------------------------------------------------------------
    # get_verbosity
    #
    @classmethod
    def get_verbosity(cls):
        """ get_verbosity

            returns Class verbosity setting
        """

        return cls.verbosity

    # -------------------------------------------------------------------------
    # set_mask_sensitivity
    #
    @classmethod
    def set_mask_sensitivity(cls, amask_sensitivity=False):
        """ set_verbosity

            mask_sensitivity = True/False
        """

        cls.mask_sensitivity = amask_sensitivity\
            if isinstance(amask_sensitivity, bool) else False

    # -------------------------------------------------------------------------
    # get_mask_sensitivity
    #
    @classmethod
    def get_mask_sensitivity(cls):
        """ get_verbosity

            returns Class mask_sensitivity setting
        """

        return cls.mask_sensitivity

    # -------------------------------------------------------------------------
    # is_str_unicode
    #
    # Returns true if String is Unicode
    #
    @staticmethod
    def is_str_unicode(astr):
        """ is_str_unicode
        Determines if a string is Unicode (return True) or not (returns False)
        to allow correct print operations.

        Used by strunicodeout function.
        Example:
            NicePrint('Checking file:[{!s}]...'.format(
                                     file.encode('utf-8') \
                                     if is_str_unicode(file) \
                                     else file))
        """
        # CODING: Python 2 and 3 compatibility
        # CODING: On Python 3 should always return False to return s
        # in the example
        #    s.encode('utf-8') if is_str_unicode(s) else s
        if sys.version_info < (3, ):
            if isinstance(astr, unicode):  # noqa
                result = True
            elif isinstance(astr, str):
                result = False
            else:
                result = False
        elif isinstance(astr, str):
            result = False
        else:
            result = False
        return result

    # -------------------------------------------------------------------------
    # strunicodeout
    #
    # Returns true if String is Unicode
    #
    @staticmethod
    def strunicodeout(astr):
        """ strunicodeout
        Outputs s.encode('utf-8') if is_str_unicode(s) else s
            NicePrint('Checking file:[{!s}]...'.format(strunicodeout(file))

        >>> import lib.NicePrint as npc
        >>> np = npc.NicePrint()
        >>> np.strunicodeout('Hello')
        'Hello'
        """
        astr = '' if astr is None else astr
        return astr.encode('utf-8') if NicePrint.is_str_unicode(astr) else astr

    # -------------------------------------------------------------------------
    # niceprint
    #
    # Print a message with the format:
    #   [2017.10.25 22:32:03]:[PRINT   ]:[uploadr] Some Message
    #
    def niceprint(self, astr, fname='uploadr', verbosity=0, logalso=0):
        """ niceprint
        Print a message with the format:
            [2017.11.19 01:53:57]:[PID       ][PRINT   ]:[uploadr] Some Message
            Accounts for UTF-8 Messages

        astr      = message to be printed
        fname     = message category
        verbosity = print if within configured verbosity: See set_verbosity
        logalso   = also issues logging. Use logging.DEBUG, logging.ERROR, etc
        """
        if logalso:
            # logging prior to masking (if enabled) to avoid double-masking
            logging.log(logalso, astr)

        if verbosity <= self.get_verbosity():
            if self.get_mask_sensitivity():
                # logging.debug('>in  astr:[%s]/type:[%s]', astr, type(astr))
                for pattern in UPLDR_K.MaskPatterns:
                    astr = re.sub(
                        pattern,
                        RedactingFormatter(None,
                                           UPLDR_K.MaskPatterns)._hashrepl,
                        astr,
                        flags=re.IGNORECASE)
                # logging.debug('<out astr:[%s]/type:[%s]', astr, type(astr))

            print('{}[{!s}][{!s}]:[{!s:11s}]{}[{!s:8s}]:[{!s}] {!s}'
                  .format(UPLDR_K.Gre,
                          UPLDR_K.Run,
                          time.strftime(UPLDR_K.TimeFormat),
                          os.getpid(),
                          UPLDR_K.Std,
                          'PRINT',
                          self.strunicodeout(fname),
                          self.strunicodeout(astr)))

    # -------------------------------------------------------------------------
    # niceassert
    #
    def niceassert(self, astr):
        """ niceassert
        Returns a message with the format:
            [2017.11.19 01:53:57]:[PID       ][ASSERT  ]:[uploadr] Message
            Accounts for UTF-8 Messages

        Usage:
            assert param1 >= 0, niceassert('param1 is not >= 0:'
                                           .format(param1))
        """
        return('{}[{!s}][{!s}]:[{!s:11s}]{}[{!s:8s}]:[{!s}] {!s}'
               .format(UPLDR_K.Red,
                       UPLDR_K.Run,
                       time.strftime(UPLDR_K.TimeFormat),
                       os.getpid(),
                       UPLDR_K.Std,
                       'ASSERT',
                       'uploadr',
                       self.strunicodeout(astr)))

    # -------------------------------------------------------------------------
    # niceerror
    #
    # Provides a messaging wrapper for logging.error, niceprint and
    # str(sys.exc_info() functions.
    #
    # Examples of use of niceerror:
    # except flickrapi.exceptions.FlickrError as ex:
    #     niceerror(caught=True,
    #               caughtprefix='+++',
    #               caughtcode='990',
    #               caughtmsg='Flickrapi exception on photos.setdates',
    #               exceptuse=True,
    #               exceptcode=ex.code,
    #               exceptmsg=ex,
    #               useniceprint=True,
    #               exceptsysinfo=True)
    # except lite.Error as e:
    #     niceerror(caught=True,
    #               caughtprefix='+++ DB',
    #               caughtcode='991',
    #               caughtmsg='DB error on INSERT: [{!s}]'
    #                         .format(e.args[0]),
    #               useniceprint=True)
    # except:
    #     niceerror(caught=True,
    #               caughtprefix='+++',
    #               caughtcode='992',
    #               caughtmsg='Caught exception in XXXX',
    #               exceptsysinfo=True)
    #
    def niceerror(self,
                  caught=False, caughtprefix='', caughtcode=0, caughtmsg='',
                  useniceprint=False,
                  exceptuse=False, exceptcode=0, exceptmsg='',
                  exceptsysinfo=''):
        """ niceerror

          caught = True/False
          caughtprefix
            ===     Multiprocessing related
            +++     Exceptions handling related
            +++ DB  Database Exceptions handling related
            xxx     Error related
          caughtcode = '000'
          caughtmsg = 'Flickrapi exception on...'/'DB Error on INSERT'
          useniceprint = True/False
          exceptuse = True/False
          exceptcode = ex.code
          exceptmsg = ex
          exceptsysinfo = True/False
        """

        if caught is not None and caught:
            logging.error('%s#%s: %s', caughtprefix, caughtcode, caughtmsg)
            if useniceprint is not None and useniceprint:
                self.niceprint('{!s}#{!s}: {!s}'
                               .format(caughtprefix, caughtcode, caughtmsg))

        if exceptuse is not None and exceptuse:
            logging.error('Error code:[%s] message:[%s]',
                          exceptcode,
                          exceptmsg)
            if useniceprint is not None and useniceprint:
                self.niceprint('Error code:[{!s}] message:[{!s}]'
                               .format(exceptcode, exceptmsg))

        if exceptsysinfo is not None and exceptsysinfo:
            logging.error(str(sys.exc_info()))
            if useniceprint is not None and useniceprint:
                self.niceprint(str(sys.exc_info()))

        sys.stderr.flush()
        if useniceprint is not None and useniceprint:
            sys.stdout.flush()

    # -------------------------------------------------------------------------
    # niceprocessedfiles
    #
    # Nicely print number of processed files
    #
    def niceprocessedfiles(self, count, ctotal, total, msg='Files Processed'):
        """
        niceprocessedfiles

        count  = Nicely print number of processed files rounded to 100's
        ctotal = Shows also the total number of items to be processed
        total  = if true shows the final count (use at the end of processing)
        """

        if not total:
            if int(count) % 100 == 0:
                self.niceprint('{!s:>15s}:[{!s:>6s}] of [{!s:>6s}]'
                               .format(msg, count, ctotal))
        else:
            if int(count) % 100 > 0:
                self.niceprint('{!s:>15s}:[{!s:>6s}] of [{!s:>6s}]'
                               .format(msg, count, ctotal))

        sys.stdout.flush()


# -----------------------------------------------------------------------------
# class RedactingFormatter wrapps logging.Formatter to mask logging messages.
#
class RedactingFormatter(logging.Formatter):
    """
        >>> import logging
        >>> import lib.NicePrint as npc
        >>> logging.basicConfig(level=logging.WARNING)
        >>> np = npc.NicePrint()
        >>> patts = (r'(?<=path:\\[).+?(?=\\])',)
        >>> for h in logging.root.handlers:
        ...     h.setFormatter(npc.RedactingFormatter(h.formatter, patts))
        >>> logging.critical('path:[somefile]') # CRITICAL:root:path:[>...<]

    """
    def __init__(self, orig_formatter, patterns):
        self.orig_formatter = orig_formatter
        self._patterns = patterns

    def _hashrepl(self, matchobj):
        # print('>in  matchobj:[{!s}]/type:[{!s}]'
        #       .format(matchobj.group(0), type(matchobj.group(0))))
        if sys.version_info < (3, ):
            # CODING: staticmethod from NicePrint NOT from instance NicePrint()
            tohash = NicePrint.strunicodeout(matchobj.group(0))
        else:
            tohash = matchobj.group(0).encode('utf- 8')

        _hexmatch = '>' + hashlib.sha1(tohash).hexdigest() + '<'

        # print('>out matchobj:[{!s}]/type:[{!s}]'
        #       .format(_hexmatch, type(matchobj.group(0))))
        return _hexmatch

    def format(self, record):
        msg = self.orig_formatter.format(record)
        for pattern in self._patterns:
            msg = re.sub(pattern, self._hashrepl, msg, flags=re.IGNORECASE)

        return msg

    def __getattr__(self, attr):
        return getattr(self.orig_formatter, attr)


# -----------------------------------------------------------------------------
# If called directly run doctests
#
if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG,
                        format='[%(asctime)s]:[%(processName)-11s]' +
                        '[%(levelname)-8s]:[%(name)s] %(message)s')

    import doctest
    doctest.testmod()
