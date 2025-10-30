import cast_upgrade_1_6_23 # @UnusedImport
from cast.application import ApplicationLevelExtension, create_link,ReferenceFinder, Bookmark, CustomObject
import logging
from builtins import len
from _collections import defaultdict
import sys
import traceback


class rexxApp(ApplicationLevelExtension):

    def __init__(self):
        ApplicationLevelExtension.__init__(self)
        self.cobol_unknown_list = []
        self.rexx_program_list_obj = defaultdict(list)
        self.new_links = []
        self.nbLinkCreated = 0
        self.unknown_objects = defaultdict(list)

    def end_application_create_objects(self, application):
 

        logging.info("Running Extension at end_application_create_objects phase")
        logging.info("****** Searching for CAST_COBOL_ProgramPrototype")

        for cobol_unknown in application.objects().has_type('CAST_COBOL_ProgramPrototype'):
            logging.info("Cobol CAST_COBOL_ProgramPrototype found: {}".format(cobol_unknown.get_name()))
            self.cobol_unknown_list.append(cobol_unknown)

        logging.info("****** Number of CAST_COBOL_ProgramPrototype {}".format(str(len(self.cobol_unknown_list))))
        
        try:
            for rexx_program in application.objects().has_type('Rexxprogram'):
                logging.info("Rexx Programs found: {}".format(rexx_program.get_name()))
                self.rexx_program_list_obj[rexx_program.get_name()].append(rexx_program)
        except Exception as e:
            exception_type, value, tb = sys.exc_info()
            logging.info('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.info(traceback_str)
                
        
        # matching by name : if CAST_COBOL_ProgramPrototype has same name as Rexx Program, they are the same object
        for cobol_unknown in self.cobol_unknown_list:
            rexx_objs = self.rexx_program_list_obj.get(cobol_unknown.get_name()) 
            if rexx_objs != None:
                for rexx_obj in rexx_objs:
                    # we have a match
                    logging.info("****** Creating Link between Unknown Cobol Program and Rexx Program")
                    link = ('matchLink', cobol_unknown, rexx_obj)
                    self.new_links.append(link)
       
        for link in  application.links().load_positions().has_caller(application.objects().has_type("CAST_JCL_Step")).has_callee(application.objects().has_type(['JCL_PROGRAM','CAST_COBOL_UtilityProgram','CAST_COBOL_ProgramPrototype'])):
            if link.get_callee().get_name() == 'IRXJCL' or link.get_callee().get_name().startswith('IKJEFT'):
                jcl_step_rexxbatch_caller = link.get_caller()
                if len(link.get_positions()) > 0:
                    bookmark_pos = link.get_positions()[0]
                    bookmark_code = bookmark_pos.get_code()
                    bookmark_lines = bookmark_code.splitlines()
                    systsin_found = "N"
                    for code_line in bookmark_lines:
                        if "PARM='" in code_line:
                            rexx_program = code_line.split("PARM='")[1].split()[0]
                            rexx_program = rexx_program.split("'")[0].split('"')[0]
                            if not '&' in rexx_program:
                                self._create_unknown_object_link(jcl_step_rexxbatch_caller,rexx_program)
                        elif code_line.startswith('//SYSTSIN') and not ' DUMMY' in code_line:
                            systsin_found = "Y"
                        elif systsin_found == 'Y':
                            if code_line.strip().startswith('ISPSTART'):
                                rexx_program = code_line.strip().split()[1].split('CMD(')[1].strip(')')
                                self._create_unknown_object_link(jcl_step_rexxbatch_caller,rexx_program)
                                systsin_found = "N"
                            elif code_line.strip().startswith('%'):
                                x  = code_line.strip().split()[0].split("%")
                                rexx_program = x[len(x)-1]
                                self._create_unknown_object_link(jcl_step_rexxbatch_caller,rexx_program)
                                systsin_found = "N"
                            #elif not ' DSN=' in code_line.strip():
                            #     rexx_program  = code_line.strip().split()[0]
                            #     self._create_unknown_object_link(jcl_step_rexxbatch_caller,rexx_program)
                            #     systsin_found = "N"
                            
    def _create_unknown_object_link(self,jcl_step_rexxbatch_caller,rexx_program): 
        link_created = "N"
        rexx_objs = self.rexx_program_list_obj.get(rexx_program) 
        if hasattr(rexx_objs, '__iter__'):
            for rexx_obj in rexx_objs:
                link = ('callLink', jcl_step_rexxbatch_caller, rexx_obj)
                self.new_links.append(link)
                link_created = "Y"
        elif rexx_objs != None: 
            link = ('callLink', jcl_step_rexxbatch_caller, rexx_objs)
            self.new_links.append(link)
            link_created = "Y"
            
                                
        if link_created == "N":    
            try:
                if self.unknown_objects.get(rexx_program) == None:
                    logging.info("Creating Unknown object for " + str(rexx_program))
                    try:
                        unknownrexxObject = CustomObject()
                        unknownrexxObject.set_name(rexx_program)
                        unknownrexxObject.set_fullname("Missing Rexx Program/%s" % (rexx_program))
                        unknownrexxObject.set_type('Unknown_Rexxprogram')
                        unknownrexxObject.set_parent(jcl_step_rexxbatch_caller)
                        unknownrexxObject.save()
                    except Exception as e:
                        exception_type, value, tb = sys.exc_info()
                        logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                        traceback_str = ''.join(traceback.format_tb(tb))
                        logging.warning(traceback_str)
                    
                    self.unknown_objects[rexx_program].append(unknownrexxObject)
                    lnk = ("callLink", jcl_step_rexxbatch_caller,unknownrexxObject)
                    self.new_links.append(lnk) 
                else:
                    for unknown_obj in self.unknown_objects.get(rexx_program):
                        lnk = ("callLink", jcl_step_rexxbatch_caller,unknown_obj)
                        self.new_links.append(lnk) 
                    
            except:
                pass  
        
    def end_application(self, application):
        
        logging.info("Running code at the end of an application")

        for link in self.new_links:
            logging.info("Link to be created is " + str(link))
            link_created = 'N'
            for unknown in application.objects().has_type('Unknown_Rexxprogram'):
                if unknown.get_fullname() == link[2].get_fullname(): 
                    l = create_link(link[0], link[1], unknown)
                        
                    if None == l:
                        logging.info("1. Could NOT create link " + str(link[0]) + " link between " + str(link[1]) + " and " + (str(link[2]._id) + '  '  + link[2].get_fullname()) if isinstance(link[2], CustomObject) else str(link[2]))
                    else:  
                        logging.info("1. Created id:" + str (l._AMTLink__id) + " " + str(link[0]) + " link between " + str(link[1]) + " and " + (str(link[2]._id) + '  '  + link[2].get_fullname()) if isinstance(link[2], CustomObject) else str(link[2]))
                        link_created = 'Y'  
                        self.nbLinkCreated += 1
     
            if link_created == 'N':
                create_link(*link) 
                self.nbLinkCreated += 1
                
        logging.info("****** Number of Links Created " + str(self.nbLinkCreated))

