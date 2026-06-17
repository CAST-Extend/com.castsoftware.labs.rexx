import cast_upgrade_1_6_25 # @UnusedImport
from cast.application import ApplicationLevelExtension, logging, create_link,ReferenceFinder, Bookmark, CustomObject
from collections import defaultdict
import sys
import traceback
import re


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
                
        
        parm_re = re.compile(r"PARM=['\"]([^'\"]+)")

        for link in  application.links().load_positions().has_caller(application.objects().has_type("CAST_JCL_Step")).has_callee(application.objects().has_type(['JCL_PROGRAM','CAST_COBOL_UtilityProgram','CAST_COBOL_ProgramPrototype'])):
            if link.get_callee().get_name() == 'IRXJCL' or link.get_callee().get_name().startswith('IKJEFT'):
                jcl_step_rexxbatch_caller = link.get_caller()
                positions = link.get_positions()
                if positions:
                    self.existing_project_link = link.get_project()
                    bookmark_pos = positions[0]
                    self.filepath = bookmark_pos.file.get_path()
                    bookmark_code = bookmark_pos.get_code() or ""
                    bookmarked_lines = bookmark_code.splitlines()
                    systsin_found = False
                    for code_line in bookmarked_lines:
                        m = parm_re.search(code_line)
                        if m:
                            rexx_program = m.group(1).split()[0]
                            if '&' not in rexx_program:
                                self._create_unknown_object_link(jcl_step_rexxbatch_caller, rexx_program)
                            continue

                        if code_line.startswith('//SYSTSIN') and ' DUMMY' not in code_line:
                            systsin_found = True
                            continue

                        if not systsin_found:
                            continue

                        stripped = code_line.strip()

                        if stripped.startswith('ISPSTART'):
                            parts = stripped.split()
                            if len(parts) > 1 and 'CMD(' in parts[1]:
                                if systsin_found or 'PARM=' in stripped.upper():
                                    cmd_part = parts[1]
                                    m = re.search(r'CMD\(\s*([^,)\s]+)', cmd_part)
                                    if m:
                                        prog = m.group(1).strip('"\'')
                                        self._create_unknown_object_link(jcl_step_rexxbatch_caller, prog)
                            systsin_found = False

                        elif stripped.startswith('%'):
                            token = stripped.split()[0]  
                            m = re.match(r'%\s*([^%\s(,]+)', token)
                            if m:
                                rexx_program = m.group(1) 
                                if (systsin_found or 'PARM=' in stripped.upper()) and rexx_program:
                                    self._create_unknown_object_link(jcl_step_rexxbatch_caller, rexx_program)
                            systsin_found = False
                        

    def create_guid(self, objectType, objectName):
        
        if not type(objectName) is str:
            return objectType + '/' + objectName.name
        else:
            return objectType + '/' + objectName
        
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
                    fullname = self.create_guid('Unknown_Rexxprogram', rexx_program) + '/' + self.filepath + '/'

                    logging.info("Creating Unknown object for " + str(rexx_program))
                    try:
                        unknownrexxObject = CustomObject()
                        unknownrexxObject.set_name(rexx_program)
                        unknownrexxObject.set_fullname(fullname)
                        unknownrexxObject.set_type('Unknown_Rexxprogram')
                        unknownrexxObject.set_parent(self.existing_project_link)
                        unknownrexxObject.set_guid(fullname)
                        unknownrexxObject.save()
                    except Exception as e:
                        exception_type, value, tb = sys.exc_info()
                        logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                        traceback_str = ''.join(traceback.format_tb(tb))
                        logging.warning(traceback_str)
                    
                    self.unknown_objects[rexx_program].append(unknownrexxObject)
                    lnk = ("callLink", jcl_step_rexxbatch_caller,rexx_program)
                    self.new_links.append(lnk) 
                else:
                    for unknown_obj in self.unknown_objects.get(rexx_program):
                        lnk = ("callLink", jcl_step_rexxbatch_caller,rexx_program)
                        self.new_links.append(lnk) 
                    
            except:
                pass  
        
    def end_application(self, application):
        
        logging.info("Running code at the end of an application")
# Build a lookup for Unknown_Rexxprogram objects by name to avoid repeated iteration
        unknowns_by_name = {u.name: u for u in application.objects().has_type('Unknown_Rexxprogram')}
        for link in self.new_links:
            logging.info("Link to be created is %s", link)
            created = False

            dest = link[2]
            # If dest is already an object, use it; otherwise try to find by name
            target_obj = dest if isinstance(dest, CustomObject) else unknowns_by_name.get(dest)

            if target_obj is not None:
                l = create_link(link[0], link[1], target_obj)
                if l is None:
                    if isinstance(target_obj, CustomObject):
                        target_info = "%s  %s" % (getattr(target_obj, '_id', 'n/a'), target_obj.get_fullname())
                    else:
                        target_info = str(target_obj)
                    logging.info("1. Could NOT create link %s link between %s and %s", link[0], link[1], target_info)
                else:
                    link_id = getattr(l, '_AMTLink__id', 'unknown')
                    if isinstance(target_obj, CustomObject):
                        target_info = "%s  %s" % (getattr(target_obj, '_id', 'n/a'), target_obj.get_fullname())
                    else:
                        target_info = str(target_obj)
                    logging.info("1.Created id:%s %s link between %s and %s", link_id, link[0], link[1], target_info)
                    created = True
                    self.nbLinkCreated += 1

            if not created:
                # Try creating the link with the original arguments; check result before incrementing
                l = create_link(*link)
                if l is None:
                    logging.info("Could NOT create link with args %s", link)
                else:
                    link_id = getattr(l, '_AMTLink__id', 'unknown')
                    logging.info("Created id:%s via create_link(*link) args %s", link_id, link)
                    self.nbLinkCreated += 1

        logging.info("****** Number of Links Created %s", self.nbLinkCreated)

