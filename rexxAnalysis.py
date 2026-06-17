import cast_upgrade_1_6_25
import cast.analysers.ua
from cast.analysers import log, CustomObject, Bookmark
from cast.application import open_source_file
import os
import sys
import traceback
import cast
from collections import OrderedDict, defaultdict
import re
import binascii


class rexxAnalysis(cast.analysers.ua.Extension):

    def __init__(self):
        
        self.extensions = ['.rexx']
        self.active = False
        self.nbrexxSRCScanned = 0
        self.nbrexxobjectscreated = 0


    def start_analysis(self):
        log.info(" Running extension code at the start of the analysis")
        try:
            options = cast.analysers.get_ua_options() #@UndefinedVariable
            if 'Rexx' not in options:
                self.active = False
            else:
                self.active = True
                self.extensions.extend(options['Rexx'].extensions)
        except Exception as e:
            exception_type, value, tb = sys.exc_info()
            cast.analysers.log.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            traceback_str = ''.join(traceback.format_tb(tb))
            cast.analysers.log.warning(traceback_str)
    
        
        
    def create_guid(self, objectType, objectName):
        
        if not type(objectName) is str:
            return objectType + '/' + objectName.name
        else:
            return objectType + '/' + objectName


    @staticmethod
    def __create_object(self, name, typ, parent, bookmark=None):
        #self.rexx_function_defn_obj = None
        fullname = self.create_guid(typ, name) + '/' + self.filepath + '/'

        try:
            if name != "":
                obj = CustomObject() 
                obj.set_name(name) 
                obj.set_guid(fullname)
                obj.set_fullname(fullname)
                obj.set_type(typ)
                obj.set_parent(parent)
                obj.save()

                log.debug('Saved object: ' + str(obj))
                obj.save_position(bookmark)

            return obj
        except Exception as e:
            log.warning('Exception while saving object ' + str(name) + ' error: ' + str(e))
            exception_type, value, tb = sys.exc_info()
            cast.analysers.log.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            traceback_str = ''.join(traceback.format_tb(tb))
            cast.analysers.log.warning(traceback_str)
            
        return None
    

    def start_file(self,file):
    

        ## test mode only
        #self.active = True
        
        if not self.active:
            return # no need to do anything

        path = file.get_path()
        _, ext = os.path.splitext(path.lower())
        
        if not ext in self.extensions:
            return

        self.project = file.get_project()
        
        self.file = file
        self.nbrexxSRCScanned += 1
        self.lineNb = 0
        self.links_yet_to_create = []
        
        """
        Scan one rexx Definition file
        """

        self.rexx_defn_obj = None
        self.rexx_defn_obj_name = ""

        try:
            with open_source_file(path) as src:
                lines = [line.rstrip('\n') for line in src]
        except Exception as e:
            log.error("Failed to open source file %s: %s", path, e)
            return

        if not lines:
            log.info("Empty source file: %s", path)
            return

        firstline = lines[0]

        second_line = lines[1] if len(lines) > 1 else ""

        if not re.search(r'/\*+.*\brexx\b', second_line, re.IGNORECASE):
            log.info("Its not a Rexx Program!!!.. ")
            return

        self.lineNb = len(lines)

        self.firstlineNb = 1
        self.lastlineNb = len(lines)

        m = re.search(r'\(([^)]+)\)', firstline)
        if m:
            self.rexx_defn_obj_name = m.group(1).upper()
        else:
            self.rexx_defn_obj_name = firstline.strip().upper()

        self.start_pos = 1
        self.last_pos = 1
        rexx_defn_obj_bookmark = Bookmark(self.file, self.firstlineNb, 1, self.lastlineNb, 1)
        self.filepath = path
        self.rexx_defn_obj = self.__create_object(self, self.rexx_defn_obj_name, "Rexxprogram", self.file, rexx_defn_obj_bookmark)
        self.nbrexxobjectscreated += 1
           

        crc = binascii.crc32("".encode()) 
        self.rexx_defn_obj.save_property('checksum.CodeOnlyChecksum', crc % 2147483648)

    def end_analysis(self):
        if not self.active:
            return


        log.info(" Statistics for AIA of REXX Source processing ")
        log.info("*****************************************************************")
        log.info(" Number of Source files Scanned " + str(self.nbrexxSRCScanned))
        log.info(" Number of Rexx Program objects created " + str(self.nbrexxobjectscreated))
        log.info("*****************************************************************")

