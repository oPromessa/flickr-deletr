"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-uploader/

    Helper class and functions for UPLoaDeR Global Constants.
"""

# -----------------------------------------------------------------------------
# Import section for Python 2 and 3 compatible code
# from __future__ import absolute_import, division, print_function,
#    unicode_literals
from __future__ import division    # This way: 3 / 2 == 1.5; 3 // 2 == 1

# -----------------------------------------------------------------------------
# Import section
#
import time
import lib.__version__ as __version__


# -----------------------------------------------------------------------------
# class Konstants wiht Global Constants and Variables for flickr-uploadr.
#
class Konstants:
    """ Konstants class

        >>> import lib.Konstants as KonstantsClass
        >>> Konstants = KonstantsClass.Konstants()
        >>> Konstants.media_count = 999
        >>> print(Konstants.media_count)
        999
        >>> print(0 < Konstants.Run < 3415)
        True
    """

    # -------------------------------------------------------------------------
    # Class Global Variables
    #   class variable shared by all instances
    #
    #   TimeFormat   = Format to display date and time. Used with strftime
    #   Version      = Version Major.Minor.Fix
    #   Run          = Unique identifier for the execution Run of this process.
    #   media_count  = Counter of total files to initially upload
    #
    media_count = None
    TimeFormat = '%Y.%m.%d %H:%M:%S'
    Run = int(time.strftime('%j')) +\
        int(time.strftime('%H'))*100 +\
        int(time.strftime('%M'))*10 +\
        int(time.strftime('%S'))

    try:
        if __version__.__version__ is not None:
            Version = __version__.__version__
        else:
            Version = '2.0.0-alpha.1'
    except (AttributeError, LookupError, NameError, TypeError, ValueError):
        Version = '2.0.0-alpha.1'

    # -------------------------------------------------------------------------
    # Color Codes for colorful output
    Std = '\033[0m'    # white (standard/normal)
    Red = '\033[31m'   # red
    Gre = '\033[32m'   # green
    Ora = '\033[33m'   # orange
    Blu = '\033[34m'   # blue
    Pur = '\033[35m'   # purple

    # Patterns to filter/ defined on UPLDR_K.MaskPatterns/mask sensitive data
    MaskPatterns = (
        # Flickr token related unformation
        # fullname="Some Name", ...
        r'(?<=(token)=).?\w+',
        r'(?<=(fullname)=).?\w+(\s*\w*){1,}',
        r'(?<=(username)=).?\w+',
        r'(?<=(user_nsid)=).?\w+',

        # Non-greedy "[filename]" preceeded by "path:[" & followed by "]"
        r'(?<=(path):\[).+?(?=\])',
        r'(?<=(loaded):\[).+?(?=\])',

        # Non-greedy "[filename]" preceeded by "Title:[" & followed by "]"
        r'(?<=title[:=]\[).+?(?=\])',
        r'(?<=file:\[).+?(?=\])',
        r'(?<=filename:\[).+?(?=\])',

        # Non-greedy "[setName]" preceeded by "Set:[" & followed by "]"
        r'(?<=set:\[).+?(?=\])',
        r'(?<=setname:\[).+?(?=\])',
        r'(?<=set to db:\[).+?(?=\])',
        r'(?<=album:\[).+?(?=\])',

        # Non-greedy "[setName]" word preceeded by "album"
        r'(?<=album)\w+',

        # Non-greedy "'api_key': " and "'secret': "
        r'(?<=key ).+?\w+',
        r'(?<=api_key\'. ).+?\w+',
        r'(?<=api_key\%).+?\w+',
        r'(?<=secret\'. ).+?\w+',

        # RAW related masking. Not being considered: tags:[xxx]
        r'(?<=raw:\[).+?(?=\])',
        r'(?<=failed:\[).+?(?=\])',
        r'(?<=JPG:\[).+?(?=\])'
        )

    # -------------------------------------------------------------------------
    # class Konstants __init__
    #
    def __init__(self):
        """ class Konstants __init__
        """
        # ---------------------------------------------------------------------
        # Instance Global Variables
        #   instance variable unique to each instance
        #
        #   base_dir      = Base configuration directory for files
        #   ini_file      = Location of INI file, normally named "uploadr.ini"
        #   etc_ini_file  = Location of INI "uploadr.ini" from ../etc folder
        #   no_delete_tag = Tag to mark files which were not delete.
        #                   Check parameter --no-delete-from-flickr
        #   upload_sleep  = Seconds to sleep prior to reattempt a failed upload
        #
        self.base_dir = str('.')
        self.ini_file = str('uploadr.ini')
        self.etc_ini_file = str('../etc/uploadr.ini')
        self.no_delete_tag = str('nodelete')
        self.upload_sleep = 20  # Normally set to 10.

    # -------------------------------------------------------------------------
    # class Konstants __rept__
    #
    def __repr__(self):
        """ class Konstants __repr__
        """

        __rep2return__ = ''
        for item in sorted([attr for attr in self.__class__.__dict__
                            if not callable(getattr(self, attr)) and
                            not attr.startswith("__")]):
            __rep2return__ += '[{!s:20s}]/type:[{!s:13s}] = [{!s:10s}]\n'\
                              .format(item,
                                      type(self.__class__.__dict__[item]),
                                      self.__class__.__dict__[item])

        return __rep2return__


# -----------------------------------------------------------------------------
# If called directly run doctests
#
if __name__ == "__main__":

    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='[%(asctime)s]:[%(processName)-11s]' +
                        '[%(levelname)-8s]:[%(name)s] %(message)s')

    import doctest
    doctest.testmod()
