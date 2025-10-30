import cast.analysers.ua
from cast.analysers import log, CustomObject, create_link, Bookmark
import cast_upgrade_1_6_23 # @UnusedImport
from cast.application import open_source_file
import os
import sys
import traceback
import cast
from collections import OrderedDict
import random
from pathlib import Path
import re
from _collections import defaultdict
import binascii


class rexxAnalysis(cast.analysers.ua.Extension):

    def __init__(self):
        
        self.nbLinksCreated = 0
        self.extensions = ['.rexx']
        self.active = False
        self.rexxfunctionlistall = defaultdict(list)
        self.rexxprocedurelistall = defaultdict(list)
        self.links_yet_to_create_end_analysis = []
        self.rexx_appdefn_main_list = []
        self.nbrexxfilesCreated = 0
        self.nbrexxfunctionCreated = 0
        self.nbrexxprocedureCreated = 0
        self.guidsToNotDuplicate = OrderedDict()
        self.nbrexxSRCScanned = 0
        self.ignore_case = re.IGNORECASE
        # List contains rexx Application and Objects
        self.rexx_procedure_regex =  '^\s*([\w\#\&@\$\-]+)+\:\s+(PROCEDURE)'
        self.rexx_function_regex =  '\s*([\w\#\&@\$\-]+)+\s*:\s*(?!PROCEDURE)'
        self.rexx_file_regex =  '\s*(?:[\"]|[\'])+EXECIO\s+(?:[0-9]+|[\*]|[\"\w]+)+\s+[diskr|diskw]+\s+([\w\#\$\@\&\-\*]+)+'
        self.call_regex =  '.*\s*CALL\s+(?:ON\s+)*([\w\#\&@\$\-]+)+\(*'
        self.call_func_proc_regex =  '\s+([\w\#\&@\$\-]+)+\('
        self.return_regex =  '\s*RETURN\s+'
        self.rexx_regexes = [ re.compile(p,self.ignore_case) for p in [ self.rexx_procedure_regex,self.rexx_function_regex, self.rexx_file_regex,self.call_regex,self.return_regex,self.call_func_proc_regex]]


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
        try:
            if name != "":
                obj = CustomObject() 
                fullname = self.create_guid(typ, name) + '/' + self.rexx_defn_obj_name + '/' + name
                obj.set_name(name) 
                if 'CustomObject' in str(type(parent)):
                    guid = str(random.randint(1, 200))+str(random.randint(1, 200))
                else:    
                    filePath = parent.get_fullname()
                    guid = filePath+str(self.guid_data)+str(random.randint(1, 200))+str(random.randint(1, 200))
                
                if not fullname in self.guidsToNotDuplicate:
                    self.guidsToNotDuplicate[fullname] = guid
                else:
                    cmpt = str(int(self.guidsToNotDuplicate[fullname]) + 1)
                    self.guidsToNotDuplicate[fullname] = cmpt
                    fullname += '_' + str(cmpt)
                

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
    

        log.info("Running code at the Startfile")
        ## test mode only
        #self.active = True
        
        if not self.active:
            return # no need to do anything
        
        filepath = file.get_path().lower()
        #_, <- because we're discarding the first part of the splitext
        _, ext = os.path.splitext(filepath)
        
        if not ext in self.extensions:
            return

        log.info("Parsing file %s..." % file)
        self.project = file.get_project()
        
        self.guid_data = Path(file.get_path()).name

        self.file = file
        filepath = file.get_path()
        self.nbrexxSRCScanned += 1
        self.lineNb = 0
        self.rexx_defn_obj = None
        self.links = []
        self.links_yet_to_create = []
        self.temp_links = []    
        self.rexxfunctionlist = defaultdict(list)
        self.rexxprocedurelist = defaultdict(list)
        self.rexxfilelist = OrderedDict()

        
        """
        Scan one rexx Definition file
        """

        
        self.caller_object = None
        self.call_to_program_obj = None
        self.meta_type = ""
        content = ""
        self.rexx_obj_created = None
        self.rexx_defn_obj = None
        self.rexx_defn_obj_name = ""

        with open_source_file(file.get_path()) as srcfile1:
            content = srcfile1.read()

        with open_source_file(file.get_path()) as srcfile1:
            mylist = [line.rstrip('\n') for line in srcfile1]
            firstline = mylist[0]
            self.firstlineNb = 1
            self.lastlineNb = len(mylist)
            self.rexx_defn_obj_name = firstline.split("(")[1].split(")")[0].upper()
            self.start_pos = 1
            self.last_pos = 1
            rexx_defn_obj_bookmark = Bookmark(self.file, self.firstlineNb, 1, self.lastlineNb, 1)
            self.rexx_defn_obj = rexxAnalysis.__create_object(self,self.rexx_defn_obj_name, "Rexxprogram", self.file, rexx_defn_obj_bookmark)
            obj_details = (self.rexx_defn_obj_name, self.rexx_defn_obj)
            self.rexx_appdefn_main_list.append(obj_details)
            self.caller_object = self.rexx_defn_obj
            self.rexx_obj_created = self.rexx_defn_obj
                     
        self.caller_bookmark = None
        crc = binascii.crc32(content.encode()) 
        self.rexx_defn_obj.save_property('checksum.CodeOnlyChecksum', crc % 2147483648)
        start_pos = 0
        end_pos = 0
        multilinecomment = 'N'
        
        with open_source_file(file.get_path()) as srcfile:
            self.rexx_function_defn_obj = None
            for line in srcfile:
                self.lineNb +=1
                if self.lineNb == 2 and not re.search(r'/\*\**\s*rexx', line, re.IGNORECASE):
                    log.info("Its not a Rexx Program!!!.. " )
                    return

                if line.lstrip().startswith("/*") and line.rstrip().endswith('*/'):
                    pass
                elif  line.lstrip().startswith("/*"):
                    multilinecomment = "Y"
                #else:
                #    multilinecomment = "N"
                    
                if self.lineNb > 2 and not line.startswith("END_PROGRAM") and multilinecomment != "Y":
                    myOnDict = [compiled_regex for compiled_regex in self.rexx_regexes if re.match(compiled_regex,line)]
                    if myOnDict:
                        only_regex = None
                        rexx_search_text = myOnDict[0].search(line)
                        only_regex = myOnDict[0].pattern
                        if rexx_search_text != None:
                            start_end_pos = rexx_search_text.span()
                            start_pos = start_end_pos[0]
                            #end_pos = start_end_pos[1]
                            end_pos = 0

                            self.caller_bookmark = Bookmark(self.file, self.lineNb , start_pos, self.lineNb, end_pos)
                            if only_regex == self.rexx_function_regex:
                                called_program_name = ""
                                called_program_name = rexx_search_text.group(0).split(':')[0].upper().strip()
                                if called_program_name != "":
                                    try:
                                        self.rexx_function_defn_obj = rexxAnalysis.__create_object(self,called_program_name, "Rexxfunction", self.rexx_defn_obj, self.caller_bookmark)
                                        self.nbrexxfunctionCreated += 1
                                        self.rexx_obj_created = self.rexx_function_defn_obj
                                        self.rexxfunctionlist[called_program_name].append(self.rexx_function_defn_obj)
                                        self.rexxfunctionlistall[called_program_name].append(self.rexx_function_defn_obj)
                                    except:
                                        pass
                            
                            elif only_regex == self.return_regex:
                                self.rexx_obj_created.save_position(self.caller_bookmark)

                            elif only_regex == self.rexx_procedure_regex:
                                called_program_name = ""
                                called_program_name = rexx_search_text.group(0).split(':')[0].upper().strip()
                                if called_program_name != "":
                                    try:
                                        self.rexx_procedure_defn_obj = rexxAnalysis.__create_object(self,called_program_name, "Rexxprocedure", self.rexx_defn_obj, self.caller_bookmark)
                                        self.nbrexxprocedureCreated += 1
                                        self.rexx_obj_created = self.rexx_procedure_defn_obj
                                        self.rexxprocedurelist[called_program_name].append(self.rexx_procedure_defn_obj)
                                        self.rexxprocedurelistall[called_program_name].append(self.rexx_procedure_defn_obj)
                                    except:
                                        pass
                            
                            elif only_regex == self.call_regex:
                                called_program_name = ""
                                called_program_name = rexx_search_text.group(0).split()[len(rexx_search_text.group(0).split())-1].strip().upper()
                                
                                link_c = "N"
                                caller_objs = self.rexxprocedurelist.get(called_program_name) 
                                if caller_objs != None:
                                    for caller_obj in caller_objs:
                                        caller_obj_fullname = caller_obj.fullname.upper()
                                        if self.rexx_defn_obj_name in caller_obj_fullname:
                                            link = ('callLink', self.rexx_obj_created, caller_obj , self.caller_bookmark)
                                            self.links.append(link)
                                            link_c = "Y"

                                if link_c == 'N':
                                    caller_objs = self.rexxfunctionlist.get(called_program_name) 
                                    if caller_objs != None:
                                        for caller_obj in caller_objs:
                                            caller_obj_fullname = caller_obj.fullname.upper()
                                            if self.rexx_defn_obj_name in caller_obj_fullname:
                                                link = ('callLink', self.rexx_obj_created, caller_obj , self.caller_bookmark)
                                                self.links.append(link)
                                                link_c = "Y"
                                       
                                    if link_c == 'N':
                                        link = ('callLink', self.rexx_obj_created, called_program_name , self.caller_bookmark)
                                        self.links_yet_to_create.append(link)
                                    
                                #log.info("self.links_yet_to_create is " + str(self.links_yet_to_create))
                            elif only_regex == self.rexx_file_regex:
                                called_program_name = ""
                                called_program_name = rexx_search_text.group(0).split()[len(rexx_search_text.group(0).split())-1].rstrip('(').strip().upper()
                                self.rexx_file_defn_obj =  None
                                if called_program_name != "":
                                    try:
                                        if self.rexxfilelist.get(called_program_name) == None:
                                            self.rexx_file_defn_obj = rexxAnalysis.__create_object(self,called_program_name, "Rexxfile", self.rexx_defn_obj, self.caller_bookmark)
                                            self.nbrexxfilesCreated += 1
                                            self.rexxfilelist[called_program_name] = self.rexx_file_defn_obj
                                        else:
                                            self.rexx_file_defn_obj = self.rexxfilelist.get(called_program_name)
                                            
                                        if 'DISKR' in rexx_search_text.group(0):
                                            link = ('accessReadLink', self.rexx_obj_created, self.rexx_file_defn_obj , self.caller_bookmark)
                                            self.links.append(link)
                                        elif 'DISKW' in rexx_search_text.group(0):
                                            link = ('accessWriteLink', self.rexx_obj_created, self.rexx_file_defn_obj , self.caller_bookmark)
                                            self.links.append(link)
                                        elif 'DISKRU' in rexx_search_text.group(0):
                                            link = ('accessReadLink', self.rexx_obj_created, self.rexx_file_defn_obj , self.caller_bookmark)
                                            self.links.append(link)
                                            link = ('accessWriteLink', self.rexx_obj_created, self.rexx_file_defn_obj , self.caller_bookmark)
                                            self.links.append(link)

                                    except:
                                        pass
                                
                            elif only_regex == self.call_func_proc_regex:
                                called_program_name = ""
                                called_program_name = rexx_search_text.group(0).split()[len(rexx_search_text.group(0).split())-1].strip().upper().strip('(')
                                
                                link_c = "N"
                                caller_objs = self.rexxprocedurelist.get(called_program_name) 
                                if caller_objs != None:
                                    for caller_obj in caller_objs:
                                        caller_obj_fullname = caller_obj.fullname.upper()
                                        if self.rexx_defn_obj_name in caller_obj_fullname:
                                            link = ('callLink', self.rexx_obj_created, caller_obj , self.caller_bookmark)
                                            self.links.append(link)
                                            link_c = "Y"

                                if link_c == 'N':
                                    caller_objs = self.rexxfunctionlist.get(called_program_name) 
                                    if caller_objs != None:
                                        for caller_obj in caller_objs:
                                            caller_obj_fullname = caller_obj.fullname.upper()
                                            if self.rexx_defn_obj_name in caller_obj_fullname:
                                                link = ('callLink', self.rexx_obj_created, caller_obj , self.caller_bookmark)
                                                self.links.append(link)
                                                link_c = "Y"
                                       
                                    if link_c == 'N':
                                        link = ('callLink', self.rexx_obj_created, called_program_name , self.caller_bookmark)
                                        self.links_yet_to_create.append(link)

                if line.rstrip().endswith('*/') and multilinecomment == "Y":
                    multilinecomment = "N"

        for link in self.links_yet_to_create:
            link_typ = link[0]
            caller_n = link[1]
            callee_n = link[2]
            link_bookmark = link[3]
            check_link_status = "N"
            
            caller_objs = self.rexxprocedurelist.get(callee_n.upper()) 
            if caller_objs != None:
                for caller_obj  in caller_objs:
                    caller_obj_fullname = caller_obj.fullname.upper().upper()
                    if self.rexx_defn_obj_name in caller_obj_fullname:
                        link = ('callLink', caller_n, caller_obj , link_bookmark)
                        self.links.append(link)
                        check_link_status = "Y"
                                
            else:
                caller_objs = self.rexxfunctionlist.get(callee_n.upper()) 
                if caller_objs != None:
                    for caller_obj in caller_objs:
                        caller_obj_fullname = caller_obj.fullname.upper()
                        if self.rexx_defn_obj_name in caller_obj_fullname:
                            link = ('callLink', caller_n, caller_obj , link_bookmark)
                            self.links.append(link)
                            check_link_status = "Y"
        
            if check_link_status == "N":
                self.links_yet_to_create_end_analysis.append(link)
                
                
        for link in self.links:
            if len(link) >= 4:
                linktype, caller_object, callee_object, nbookmark = link
            else:
                linktype, caller_object, callee_object = link
            if 'cast' in str(type(caller_object)) and 'cast' in str(type(callee_object)):
                if link not in self.temp_links:
                    self.temp_links.append(link) 
                    
        
        for link in self.temp_links:
            self.nbLinksCreated += 1
            log.info(' Link created between ' + str(link[0]) + ' and '  + str(link[1]) + str(link[2]) )
            create_link(*link)          
                                    
                
    def end_analysis(self):
        if not self.active:
            return


        self.links = []
        self.temp_links = []
        
        
        for link in self.links_yet_to_create_end_analysis:
            link_typ = link[0]
            caller_n = link[1]
            callee_n = link[2]
            link_bookmark = link[3]
            check_link_status = "N"
            
            caller_objs = self.rexxprocedurelistall.get(callee_n.upper()) 

            if caller_objs != None:
                for caller_obj in caller_objs:
                    caller_obj_fullname = caller_obj.fullname.upper()
                    link = ('callLink', caller_n, caller_obj , link_bookmark)
                    self.links.append(link)
                    check_link_status = "Y"
                                
            else:
                caller_objs = self.rexxfunctionlistall.get(callee_n.upper()) 

                if caller_objs != None:
                    for caller_obj in caller_objs:
                        caller_obj_fullname = caller_obj.fullname.upper()
                        link = ('callLink', caller_n, caller_obj , link_bookmark)
                        self.links.append(link)
                        check_link_status = "Y"
                        
                                        
        for link in self.links:
            #log.info(" link is " + str(link))
            if len(link) >= 4:
                linktype, caller_object, callee_object, nbookmark = link
            else:
                linktype, caller_object, callee_object = link
            if 'cast' in str(type(caller_object)) and 'cast' in str(type(callee_object)):
                if link not in self.temp_links:
                    self.temp_links.append(link) 
                    
        
        for link in self.temp_links:
            self.nbLinksCreated += 1
            log.info(' Inter file Link created between ' + str(link[0]) + ' and '  + str(link[1]) + str(link[2]) )
            create_link(*link)          
                                    
                

        log.info(" Statistics for AIA of REXX Source processing ")
        log.info("*****************************************************************")
        log.info(" Number of Source files Scanned " + str(self.nbrexxSRCScanned))
        log.info(" Number of Links Created " + str(self.nbLinksCreated))
        log.info("*****************************************************************")

