import cast_upgrade_1_6_23 # @UnusedImport
from cast.application import ApplicationLevelExtension, ReferenceFinder,\
    Bookmark,open_source_file
import logging
import re
import os
import random
from html import unescape
from pathlib import Path
import traceback
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter

class db2oraclemigrationExtensionApplication(ApplicationLevelExtension):

    def __init__(self): 
        self.currentsrcfile=""
        self.sregex = ""
        self.sgobjname=""
        self.filename = ""
        self.xmlfile = ""
        self.file = ""    
        self.propvalue=[]
        self.uniqueobjlist =[]
        self.cob_objects = {}
        self.sql_objects = {}
        self.sql_objects_create_table = {}
        self.saved_objects_prop = {}
        self.search_cache = {}
        pass     
    
    def init_search_cache(self, application):
        logging.info("-------------------------------")
        logging.info("Loading search_cache [start]")
        icounter = 0
        for obj in application.objects():
            icounter+=1
            #if icounter == 0 or (icounter % icounter_reporting == 0)or icounter == len(application_objects):
            #    logging.debug("  Processing object #" % str(len(icounter))) 
            object_name = obj.get_name()
            obj_found = self.search_cache.get(object_name)
            if not obj_found:
                self.search_cache[object_name] = []
                obj_found = self.search_cache[object_name]
            obj_found.append(obj)
        logging.info("Loading search_cache [end]")

        
            
    def end_application(self, application):
        logging.info("Running code at the end of an application in db2oraclemigration")
        self.application = application
        self.init_search_cache(application)
        self.setdeclareproperty()

        s= self.get_plugin()
        #logging.info(str(s.get_plugin_directory()))
        try:
            self.xmlfile =str(s.get_plugin_directory())+ "\\parsedefine.xml" 
            if (os.path.isfile(self.xmlfile)):
                        tree = ET.parse(self.xmlfile, ET.XMLParser(encoding="UTF-8"))
                        root=tree.getroot()
            logging.debug(str(self.xmlfile));
        except ET.ParseError as err:
            logging.info(": error  saving property violation   : %s", str(err))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(err))
            logging.warning(traceback_str)

            return tree

        logging.info("Processing Step 1a - Parsing Cobol SQL query out of 5 steps")

        self.cob_objects_to_check = ['CAST_Cobol_SQLQuery','CAST_IMS_SQLQuery']
        self.jcl_objects_to_check = ['CAST_JCL_SQLQuery']

        appcobfiles = [
            o for o in application.get_files(['CAST_COBOL_SavedProgram','CAST_COBOL_Copybook'])
            if o.get_path() 
        ]
        
        logging.info("appcobfiles is " + str(appcobfiles))
        appcobfiles_count = len(appcobfiles) 
    
        
        try:
            for index, o in enumerate(appcobfiles, start=1):   
                logging.info("Processing Cobol file " + str(index) + " out of " + str(appcobfiles_count))
                self.fileobject = o
                self.get_cob_search(root)
        except:
            pass  
        

        #cobol_jcl_sqlqueryobjects = application.objects().has_type(['CAST_Cobol_SQLQuery','CAST_IMS_SQLQuery','CAST_JCL_SQLQuery']).load_positions()
    
        
        #cobol_jcl_sqlqueryobjects_count = cobol_jcl_sqlqueryobjects.count() 
    
        #try:
        #    for index, o in enumerate(cobol_jcl_sqlqueryobjects, start=1):   
        #        if  len(o.get_positions()) > 0:
        #            pattern = r'^\s*(OPEN|CLOSE|INCLUDE)'
        #            bookmark = o.get_positions()[0]
        #            if not re.match(pattern, o.get_name(), re.IGNORECASE):
        #                self.cob_objects[o] = bookmark
        #except:
        #    pass
        
        #self.get_cob_search(root)

        #try:
        #    for o in application.objects().has_type(['SQLScriptSchema','SQLScriptTable','SQLScriptIndex',
        #             'SQLScriptProcedure','SQLScriptDML','SQLScriptFunction','SQLScriptView','SQLScriptTrigger',
        #             'SQLScriptPackage','SQLScriptType','SQLScriptForeignKey','SQLScriptUniqueConstraint','SQLScriptEvent',
        #             'SQLScriptSynonym','SQLScriptTableSynonym','SQLScriptViewSynonym','SQLScriptFunctionSynonym',
        #             'SQLScriptProcedureSynonym','SQLScriptPackageSynonym','SQLScriptTypeSynonym','SQLScriptMethod']).load_positions():
        #        if  len(o.get_positions()) > 0:
        #            self.sql_objects[o] = o.get_positions()[0]
        #            if o.get_type() in ['SQLScriptTable','SQLScriptTableSynonym']:
        #                self.sql_objects_create_table[o] = o.get_positions()[0]
        #except:
        #    pass      
 
        logging.info("Processing Step 2a-Parsing SQL file out of 5 steps")
       
        appsqlfiles = [o for o in application.search_objects(category='sourceFile') if o.get_path() and o.get_path().lower().endswith('.sql')]

        appsqlfiles_count = len(appsqlfiles) 
    

        try:
            for index, o in enumerate(appsqlfiles, start=1):   
                logging.info("Processing SQL file " + str(index) + " out of " + str(appsqlfiles_count))
                self.fileobject = o
                self.getsqlsearch_object(root)
        except:
            pass  
        #self.getsqlsearch_object(root)

        logging.info("Processing Step 3-Parsing Java file out of 5 steps")
                
        for o in application.search_objects(category='JV_FILE'):
      
            # check if file is analyzed source code, or if it generated (Unknown)
            if not o.get_path():
                continue
            
            if not (o.get_path().lower().endswith('.java')):
                continue
            #cast.analysers.log.debug("file found: >" + str(o.get_path()))
            logging.debug("file found: >" + str(o.get_path()))
             
            if (o.get_path().lower().endswith('.java')):  
                self.getJavafilesearch(o, root)
                 
        logging.info("Processing Step 4-Parsing properties file out of 5 steps")
                 
        for o in application.search_objects(category='sourceFile'):
           
            # check if file is analyzed source code, or if it generated (Unknown)
            if not o.get_path():
                continue
            
            ##specific requirement to scan only SQL Files
            
            if not (o.get_path().lower().endswith('sql.properties')):
                continue
            #cast.analysers.log.debug("file found: >" + str(o.get_path()))
            logging.debug("file found: >" + str(o.get_path()))
         
            if (o.get_path().lower().endswith('sql.properties')):
                self.getpropertiessearch(o, root)
                

        logging.info("Processing Step 5-Parsing properties file out of 5 steps")
        
        shell_file_extns = ['.ksh','.sh','.ssh','.csh','.bsh','.shell','.bash','.tcsh','.pl']
        ## SCAN SHELL.
        for o in application.search_objects(category='sourceFile'):
           
            # check if file is analyzed source code, or if it generated (Unknown)
            if not o.get_path():
                continue

            _, sfilext = os.path.splitext(o.get_path().lower())
                        
            if sfilext.lower() in shell_file_extns:            
                #cast.analysers.log.debug("file found: >" + str(o.get_path()))
                logging.debug("file found: >" + str(o.get_path()))
                self.getpropertiessearch(o, root)
                    
       
#             
            #self.scan_Sql(application, o)               

    def setdeclareproperty(self):
        
        declarelist=['sourceFile', 'SQLScriptSchema','SQLScriptTable','SQLScriptIndex',
                     'SQLScriptProcedure','SQLScriptDML','SQLScriptFunction','SQLScriptView','SQLScriptTrigger',
                     'SQLScriptPackage','SQLScriptType','SQLScriptForeignKey','SQLScriptUniqueConstraint','SQLScriptEvent',
                     'SQLScriptSynonym','SQLScriptTableSynonym','SQLScriptViewSynonym','SQLScriptFunctionSynonym',
                     'SQLScriptProcedureSynonym','SQLScriptPackageSynonym','SQLScriptTypeSynonym','SQLScriptMethod','JV_METHOD', 'JV_GENERIC_METHOD', 
                     'JV_INST_METHOD', 'JV_INST_CLASS', 'JV_CTOR', 'JV_GENERIC_CTOR', 'JV_FILE', 'JV_INST_CTOR', 'JV_INTERFACE', 'JV_GENERIC_INTERFACE', 
                     'JV_INST_INTERFACE', 'JV_GENERIC_CLASS','JV_PROJECT', 'JV_PACKAGE', 'JV_CLASS','CAST_Cobol_SQLQuery','CAST_IMS_SQLQuery','CAST_JCL_SQLQuery']
        for declareitems in declarelist: 
               self.application.declare_property_ownership('dboraclemigrationScript.CONCAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NEXT_VALUE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RESULT_SET_LOCATOR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DAYS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MINUTES',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SYSDUMMY1',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.WITH_UR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FETCH',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.EXCEPT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.ATANH',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BIGINT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BITANDNOT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BITOR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BITNOT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BITXOR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CHARACTER_LENGTH',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CHAR_LENGTH',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.COT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CURRENT_DATE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CURRENT_SERVER',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SQLID',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TIME',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CURRENT_USER',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CURSOR_ROWCOUNT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DAY',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DAYNAME',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DAYOF',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DBCLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DECFLOAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DECIMAL',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DIGITS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DOUBLE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.EMPTY_DBCLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.EMPTYNCLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FLOAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.HEX',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.HOUR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.INSERT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.INT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.JULIAN',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LCASE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LEFT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LOCATE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LOG10',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LONG_VARCHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LONG_VARGRAPHIC',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MAX',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MIN',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MINUTE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MONTH',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MONTHNAME',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MULTIPLY_ALT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MICROSECOND',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.MIDNIGHT_SECONDS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NCHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NCLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NVARCHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NVL',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.OCT_LENGHT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.QUARTER',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RADIANS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RAISE_ERROR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RAND',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FunctionREAL',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.REPEAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RIGHT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SECOND',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FunctionSMALLINT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SPACE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.STRIP',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TIMEStamp',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TIMESTAMPDIFF',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TRUNC_TIMESTAMP',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TRUNCATE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.UCASE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VALUE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARCHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARCHAR_BIT_FORMER',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARCHAR_FORMAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARCHAR_FORMAT_BIT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARGRAPHIC',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.WEEK',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLDOCUMENT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLNAMESPACES',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLROW',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLTEXT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLVALIDATE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XMLXMLXSROBJECTID',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.YEAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEBIGINT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CHAR_FOR_BIT_DATA',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CHAACTER_VARYING',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEDBCLOB',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEDECIMAL',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEDECFLOAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEFLOAT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEGRAPHIC',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.INTEGER',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NCHAR_VARYING',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.NUMERIC',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.REAL',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SMALLINT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPETIME',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATATYPEVARCHAR',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARCHAR_FOR_BIT_DATA',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VARGRAPHIC',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.XML',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SNAPSHOT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LOAD',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.dynexpln',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.SNAP',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.IMPORT_EXPORT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.db2HistoryFcts',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.REGEXP_REPLACE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.HEXTORAW',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LOCALTIMESTAMP',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.GLOBAL_TEMPORARY_TABLE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LISTAGG',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LPAD',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.LTRIM',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.OVERLAY',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.REPLACE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RPAD',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.RTRIM',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.TRANSLATE',[declareitems])
                #end
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.Built_in_SQL_Functions_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.SQL_language_elements_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.Datetime_interval_expressions_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.Data_Types_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.SELECT_Statement_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigration_CustomMetrics.CREATE_TABLE_statement_variations',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.GENERATED_ALWAYS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.BYDEFAULT_ASIDENTITY',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FORCOLUMN',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FORBITDATA',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FORSBCS',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.FORMIXED',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.CCSID',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DEFAULT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.DATACAPTURE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.AUDIT',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.WITH_RESTRICT_ON_DROP',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.VOLATILE',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.APPEND',[declareitems])
               self.application.declare_property_ownership('dboraclemigrationScript.PARTITION',[declareitems])



    def get_cob_search(self, root):

        logging.info("File Cobol analysis started.")
        
        try:
            self.pattern_dict = defaultdict(list)
            self.pattern_dict_create_table = defaultdict(list)
            self.pattern_per_category_dict = defaultdict(list)

            for group in root.findall('cobSearch'):
                self.sregex = unescape(group.find('RegexPattern').text)
                #logging.debug("---" + str(self.sregex) + "---")
                
                sobjname = group.find('propertyname').text
                sviolation = group.find('Rulename').text 
                #logging.info(str(sobjname) + " Reg ex--->" + str(self.sregex))
                val = [sobjname, sviolation]
                self.pattern_dict[self.sregex].append(val)
                self.pattern_per_category_dict[sviolation].append(self.sregex)

            self.uniqueobjlist = []
            self.saved_objects_prop = {}

            with open_source_file(self.fileobject.get_path()) as srcfile:
                for linenum, line in enumerate(srcfile, start=1):
                    line = line[7:]
                    if not (line.strip().startswith('*') or line.strip().startswith('*>')):
                        self.sqlcobobj = self.find_most_specific_object_type(self.fileobject,linenum, 1,self.cob_objects_to_check)
                        if self.sqlcobobj.get_type() in self.cob_objects_to_check:
                            self.violation_bookmark = Bookmark(self.sqlcobobj,linenum,-1,linenum,-1 )
                            self.set_sql_file_new(line,self.pattern_dict) 
                            #self.set_sql_file_mmr(line,self.pattern_per_category_dict)
                           
            # Process each SQL file 
            #logging.info("self.sql_objects is " + str(len(self.sql_objects)))
            
            #for sqlobj, objpos in self.sql_objects_create_table.items():
            #    logging.info('Scanning SQL Object for create table variations: ' + str(sqlobj.get_name()))
            #    self.set_cobol_sql_new([sqlobj, objpos],self.pattern_dict_create_table) 
                
            #for sqlobj, objpos in self.sql_objects.items():
            #    logging.info('Scanning SQL Object: ' + str(sqlobj.get_name()))
            #    self.set_cobol_sql_new([sqlobj, objpos],self.pattern_dict) 

            logging.info("Processing Step 2b.")
            self.unique_obj_count = Counter(self.uniqueobjlist)
            self.unique()
                
        except Exception as e:
            logging.info(": error db2oracle extension set : " + str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return
        


    #def get_cob_search(self, root):
    #    logging.info("File COBOL analysis started.")
    #    
    #    try:
    #        total_elements = len(root.findall('Search'))
    #        self.pattern_dict = defaultdict(list)
    #
    #        for group in root.findall('cobSearch'):
    #            self.sregex = group.find('RegexPattern').text
    #            sobjname = group.find('propertyname').text 
    #            rulen = group.find('Rulename').text     
    #
    #            # Add the rule name and object name for each regex pattern
    #            val = [sobjname, rulen]
    #            self.pattern_dict[self.sregex].append(val)    
    #
    #        total_cobol_sql_query_count = len(self.cob_objects)
    #        logging.info("Total Number of Cobol-JCL SQL Query Objects " + str(total_cobol_sql_query_count))
    #
    #        # Process each cobol object and its corresponding property
    #        for index, (cobobj, bookmark) in enumerate(self.cob_objects.items(), start=1):
    #            logging.info("Processing SQL Query object " + str(index) + " out of " + str(total_cobol_sql_query_count))
    #            self.set_cobol_sql_new([cobobj, bookmark],self.pattern_dict) 
    #            
            
            
    #        self.unique()

        except Exception as e:
            logging.error("Error in DB2Oracle extension set: %s", str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('Exception Type: ' + str(exception_type) + ' | Error Message: ' + str(e))
            return

    def set_sql_file_new(self, line,pattern_dict_to_check):

        self.sql_regexps = []
        self.cobol_sqlquery = line

        self.pattern_list_value = pattern_dict_to_check.copy()

        # Process the regex patterns and store them
        for key, value in pattern_dict_to_check.items():
            key = key.replace('\\\\', '\\')  # Correct double backslashes
            text = re.compile(key, re.IGNORECASE)
            self.sql_regexps.append(text)
        
        try:
        
            # Process each line
            # Search for matches in the query using regex
            for regexp in self.sql_regexps:
                checkmatch = re.search(regexp, self.cobol_sqlquery)
                if checkmatch:
                    regexp = regexp.pattern
                    start_pos = checkmatch.start()
                    #line_number = self.cobol_sqlquery.count('\n', 0, start_pos) + self.sqlcobobj_linenum
                    #logging.info("line_number is " + str(line_number)) 
                    
                    # Process each matching pattern
                    value_processed = False
                    for key, value in self.pattern_list_value.items():
                        if key.replace('\\\\', '') == regexp:
                            value_processed = True
                            for val in value:
                                sobjname, rulename = val
                                self.uniqueobjlist.append(sobjname + "cast" + str(self.sqlcobobj)+"|"+self.sqlcobobj.get_name()+"|"+self.sqlcobobj.get_fullname())
                                if self.sqlcobobj.id not in self.saved_objects_prop:
                                    try:
                                        self.sqlcobobj.save_violation('dboraclemigration_CustomMetrics.' + rulename, self.violation_bookmark)
                                        #logging.info("Violation saved: >" + 'dboraclemigration_CustomMetrics.' + rulename + " pattern is " + str(sobjname) + " for object " + str(self.sqlcobobj))
                                    except Exception as e:
                                        logging.error(": error saving property violation : %s", str(e))
                                        exception_type, value, tb = sys.exc_info()
                                        traceback_str = ''.join(traceback.format_tb(tb))
                                        logging.warning(traceback_str)
                                        logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                                        logging.warning(traceback_str)
                                        #if hasattr(e, 'Property already saved for object'):
                                        #    continue  # Skip if already saved
                                else:
                                    self.saved_objects_prop[self.sqlcobobj.id] = rulename

        
                            if value_processed:
                                break

        
        except Exception as e:
            logging.error(": error saving property violation : %s", str(e))
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
        
        return
    """
    def set_sql_file_mmr(self, line, pattern_per_category_dict):

        self.sql_regexps = {}
        self.cobol_sqlquery = line

        # Process the regex patterns and store them
        for key, regexp_values in pattern_per_category_dict.items():
            value = '|'.join(regexp_values.replace('\\\\', '\\')) # Correct double backslashes
            text = re.compile(value, re.IGNORECASE)
            self.sql_regexps[text] = key 
        
        try:
        
            # Process each line
            # Search for matches in the query using regex
            for regexp in self.sql_regexps:
                checkmatch = re.search(regexp, self.cobol_sqlquery)
                if checkmatch:
                    regexp = regexp.pattern
                    start_pos = checkmatch.start()
                    #line_number = self.cobol_sqlquery.count('\n', 0, start_pos) + self.sqlcobobj_linenum
                    #logging.info("line_number is " + str(line_number)) 
                    
                    # Process each matching pattern
                    value_processed = False
                    key = self.sql_regexps[text]
                    self.uniqueobjlist.append(rulename + "cast" + str(self.sqlcobobj)+"|"+self.sqlcobobj.get_name()+"|"+self.sqlcobobj.get_fullname())
                    if self.sqlcobobj.id not in self.saved_objects_prop:
                        try:
                            self.sqlcobobj.save_violation('dboraclemigration_CustomMetrics.' + rulename, self.violation_bookmark)
                            #logging.info("Violation saved: >" + 'dboraclemigration_CustomMetrics.' + rulename + " pattern is " + str(sobjname) + " for object " + str(self.sqlcobobj))
                        except Exception as e:
                            logging.error(": error saving property violation : %s", str(e))
                            exception_type, value, tb = sys.exc_info()
                            traceback_str = ''.join(traceback.format_tb(tb))
                            logging.warning(traceback_str)
                            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                            logging.warning(traceback_str)
                            #if hasattr(e, 'Property already saved for object'):
                            #    continue  # Skip if already saved
                    else:
                        self.saved_objects_prop[self.sqlcobobj.id] = rulename


        
        except Exception as e:
            logging.error(": error saving property violation : %s", str(e))
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
        
        return
    """
    def set_cobol_sql_new(self, sqlobjprop, pattern_dict_to_check):
        # One regular expression for multiple patterns
        count = 0
        ttl_key_processed = 0
        extract_data = 'N'
        self.sql_regexps = []
        self.sqlcobobj = sqlobjprop[0]
        self.sqlcobobj_pos = sqlobjprop[1]
        self.sqlcobobj_pos_begin_line = self.sqlcobobj_pos.begin_line
        self.cobol_sqlquery = self.sqlcobobj_pos.get_code()

        self.pattern_list_value = pattern_dict_to_check.copy()

        # Process the regex patterns and store them
        for key, value in pattern_dict_to_check.items():
            key = key.replace('\\\\', '\\')  # Correct double backslashes
            text = re.compile(key, re.IGNORECASE)
            self.sql_regexps.append(text)
        
        self.ref_sql_check()

        return 

    def ref_sql_check(self):
        
        set_sqlobjbookmark = ""
        sqlquery = ""
        #text_split = self.objprop.split('Sqlquery->')
        self.query_list = []
        
        objtype = self.sqlcobobj.get_type()
        # Split and process queries
        #for query in text_split:
        #    if 'Bookmark_pos->' in query:
        #        query_split = query.split('Bookmark_pos->')
        #        for query2 in query_split:
        #            if 'Bookmark' in query2:
        #                self.cobpropbookmark = query2
        #            elif query2 != "":
        #                a = [self.cobpropbookmark, query2]
        #self.query_list.append(sqlquery)
                
        try:
            self.uniqueobjlist = []
        
            # Process each query
            # Search for matches in the query using regex
            for regexp in self.sql_regexps:
                checkmatch = re.search(regexp, self.cobol_sqlquery)
                if checkmatch:
                    regexp = regexp.pattern
                    start_pos = checkmatch.start()
                    line_number = self.cobol_sqlquery.count('\n', 0, start_pos) + self.sqlcobobj_pos_begin_line
                    #logging.info("line_number is " + str(line_number)) 
                    
                    # Process each matching pattern
                    value_processed = False
                    for key, value in self.pattern_list_value.items():
                        if key.replace('\\\\', '') == regexp:
                            value_processed = True
                            for val in value:
                                sobjname, rulename = val
                                obj = self.sqlcobobj
                                self.uniqueobjlist.append(sobjname + "cast" + str(obj)+"|"+obj.get_fullname())
                                try:
                                    violation_bookmark = Bookmark(obj,line_number,-1,line_number,-1 )
                                    #logging.info("violation_bookmark " + str(violation_bookmark))
                                    obj.save_violation('dboraclemigration_CustomMetrics.' + rulename, violation_bookmark)
                                    logging.info("Violation saved: >" + 'dboraclemigration_CustomMetrics.' + rulename + " pattern is " + str(sobjname))
                                except Exception as e:
                                    logging.error(": error saving property violation : %s", str(e))
                                    exception_type, value, tb = sys.exc_info()
                                    traceback_str = ''.join(traceback.format_tb(tb))
                                    logging.warning(traceback_str)
                                    logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                                    logging.warning(traceback_str)
                                    if hasattr(e, 'Property already saved for object'):
                                        continue  # Skip if already saved
        
                            if value_processed:
                                break

        except Exception as e:
            logging.error(": error saving property violation : %s", str(e))
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
        
        return

    def getsqlsearch_object(self, root):

        logging.info("File SQL analysis started %s" % str(self.fileobject.get_path()))
        
        try:
            self.pattern_dict = defaultdict(list)
            self.pattern_dict_create_table = defaultdict(list)
            self.pattern_per_category_dict = defaultdict(list)

            for group in root.findall('Search'):
                self.sregex = unescape(group.find('RegexPattern').text)
                #logging.debug("---" + str(self.sregex) + "---")
                
                sobjname = group.find('propertyname').text
                sviolation = group.find('Rulename').text 
                #logging.info(str(sobjname) + " Reg ex--->" + str(self.sregex))
                val = [sobjname, sviolation]
                if sviolation != 'CREATE_TABLE_statement_variations':
                    self.pattern_dict[self.sregex].append(val)
                else:
                    self.pattern_dict_create_table[self.sregex].append(val)
                self.pattern_per_category_dict[sviolation].append(self.sregex)
                    
            self.uniqueobjlist = []
            self.saved_objects_prop = {}

            count_lines = 0
            with open_source_file(self.fileobject.get_path()) as srcfile:
                count_lines = sum(1 for _ in srcfile)
            with open_source_file(self.fileobject.get_path()) as srcfile:
                icounter_reporting = 1000
                for linenum, line in enumerate(srcfile, start=1):
                    if linenum == 1 or (linenum % icounter_reporting == 0)or linenum == count_lines:
                        logging.debug("  Processing line #%s of of %s" % (str(linenum),str(count_lines)))
                    if not line.startswith('--'):
                        self.sqlcobobj = self.fileobject.find_most_specific_object(linenum, 1)
                        self.violation_bookmark = Bookmark(self.sqlcobobj,linenum,-1,linenum,-1 )
                        self.set_sql_file_new(line,self.pattern_dict_create_table)            
                        self.set_sql_file_new(line,self.pattern_dict) 
                        #self.set_sql_file_mmr(line,self.pattern_per_category_dict)
                           
            # Process each SQL file 
            #logging.info("self.sql_objects is " + str(len(self.sql_objects)))
            
            #for sqlobj, objpos in self.sql_objects_create_table.items():
            #    logging.info('Scanning SQL Object for create table variations: ' + str(sqlobj.get_name()))
            #    self.set_cobol_sql_new([sqlobj, objpos],self.pattern_dict_create_table) 
                
            #for sqlobj, objpos in self.sql_objects.items():
            #    logging.info('Scanning SQL Object: ' + str(sqlobj.get_name()))
            #    self.set_cobol_sql_new([sqlobj, objpos],self.pattern_dict) 

            logging.info("Processing Step 2b.")
            self.unique_obj_count = Counter(self.uniqueobjlist)
            self.unique()
                
        except Exception as e:
            logging.info(": error db2oracle extension set : " + str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return
        
    def find_most_specific_object(self, _file, linenum, columnnum):
        """
        Find the most specific sub object containing line, column of a given type
        """
            
        result = _file
        result_position = None
        for sub_object in _file.load_objects():
            for position in sub_object.get_positions():
                if position.contains_position(linenum, columnnum) and (not result_position or result_position.contains(position)):
                    result = sub_object
                    result_position = position
                   
                    # first one having correct type :
        return result     

    def find_most_specific_object_type(self, _file, linenum, columnnum, _type):
        """
        Find the most specific sub object containing line, column of a given type
        """
        
        linenum = int(linenum)
        columnnum = int(columnnum)
            
        result = _file
        result_position = None
    
        for sub_object in _file.load_objects():
            for position in sub_object.get_positions():
                bookmark_str = str(sub_object)
                object_type = bookmark_str.split(",")[1].split(")")[0]
                
                if object_type.strip() in _type:
                    if position.contains_position(linenum, columnnum) and (not result_position or result_position.contains(position)):
                        result = sub_object
                        result_position = Bookmark(_file, linenum, columnnum, linenum+1, columnnum) 
                        if result.get_type() in _type:
                            return result
        
        return result

    def getsqlsearch(self,  file, root): 
        logging.info("file sql start")
        
        try:
            for group in root.findall('Search'):
                self.sregex = unescape(group.find('RegexPattern').text)
                logging.info("---" + str(self.sregex) + "---")
                
                if file.get_name().lower().endswith('.sql'):
                    logging.info('Scanning sql file :' + str(Path(file.get_path()).name))
                    if os.path.isfile(file.get_path()):
                        sobjname = group.find('propertyname').text
                        self.currentsrcfile = file
                        self.sgobjname = sobjname
                        sviolation = group.find('Rulename').text 
                        #logging.info(str(sobjname) + " Reg ex--->" + str(self.sregex))
                        self.setpropjavasql(file, sobjname, sviolation)
        
        except Exception as e:
            logging.info(": error db2oracle extension set : " + str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return
 
        
        
    def getpropertiessearch(self,  file, root): 
        logging.info("Properties start")
       
        try:
                    for group in root.findall('propertiesfileSearch'):
                        self.sregex = unescape(group.find('RegexPattern').text)
                        logging.debug("---"+str(self.sregex)+ "---")
                                   
                        if (os.path.isfile(file.get_path())):
                            sobjname = group.find('propertyname').text 
                            self.currentsrcfile= file
                            self.sgobjname=sobjname
                            sviolation = group.find('Rulename').text 
                            logging.debug(str(sobjname)+"Reg ex--->"+str(self.sregex) )
                            if file.get_name().endswith('.properties'):
                                logging.info('Scanning properties  file :'+str(Path(file.get_path()).name))
                                self.setprop(file, sobjname, sviolation); 
                            else:
                                logging.info('Scanning shell  files :'+str(Path(file.get_path()).name))
                                self.setprop(file, sobjname, sviolation,'shell'); 
                                

        except Exception as e:
            logging.info(": error  db2oracle extension  properties search  : %s", str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return  
                                
    def getJavafilesearch(self,  file,  root): 
        logging.info("java file start")
       
        try:
                    for group in root.findall('javafileSearch'):
                        self.sregex = unescape(group.find('RegexPattern').text)
                        logging.debug("---"+str(self.sregex)+ "---")
                                   
                        if file.get_name().endswith('.java'):
                            logging.info('Scanning java  file :'+str(Path(file.get_path()).name))
                            if (os.path.isfile(file.get_path())):
                                sobjname = group.find('propertyname').text 
                                self.currentsrcfile= file
                                self.sgobjname=sobjname
                                sviolation = group.find('Rulename').text 
                                logging.debug(str(sobjname)+"Reg ex--->"+str(self.sregex) )
                                self.setpropjavasql(file, sobjname, sviolation); 
                                      
        except Exception as e:
            logging.info(": error  db2oracle extension  java search  : %s", str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return  
        # Final reporting in ApplicationPlugins.castlog
        
    def setpropjavasql(self, file, sobjname, rulename):
            # one RF for multiples patterns
        rfCall = ReferenceFinder()
        rfCall.add_pattern(('srcline'), before='', element=self.sregex, after='')  # requires application_1_4_7 or above
        
        # search all patterns in the current program
        try:
            self.propvalue = []
            self.uniqueobjlist = []
            cntj = 0
            references = [reference for reference in rfCall.find_references_in_file(file)]
            
            for reference in references:
                linenb = reference.bookmark.begin_line
                obj = file.find_most_specific_object(linenb, 1)
                cntj += 1
                self.uniqueobjlist.append(sobjname + "cast" + str(obj))
                obj.save_violation('dboraclemigration_CustomMetrics.' + rulename, reference.bookmark)
                #logging.info("violation saved: >" + 'dboraclemigration_CustomMetrics.' + rulename + "  line:::" + str(reference.value) + " obj is " + str(obj) + str(reference.bookmark))
        
            self.unique()
        
        except Exception as e:
            logging.info(": error saving property violation : " + str(e))  
            exception_type, value, tb = sys.exc_info()
            traceback_str = ''.join(traceback.format_tb(tb))
            logging.warning(traceback_str)
            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            logging.warning(traceback_str)
            return


    def unique_new(self):
        unique_set = set(self.uniqueobjlist)   
    
        for x in unique_set:
            temp_x = x
            logging.info("temp_x " + str(temp_x))
            x = x.split("|")[0]
            x = x.replace('castObject', ',').replace('castFile', ',').replace('(', '').replace(')', '')

            # Split the string once and reuse the result
            parts = x.split(',')
            if len(parts) < 3:  # Ensure there are enough parts in the split result
                logging.warning("Invalid format in x: " + str(x))
                continue
            
            dbtype = parts[0].strip()
                        
            try:
                cnt = str(self.uniqueobjlist.count(temp_x))
                self.sqlcobobj.save_property('dboraclemigrationScript.' + dbtype, cnt)
                logging.info("Property saved: ---> dboraclemigrationScript." + dbtype + " in obj " + str(self.sqlcobobj.get_name()) + " " + cnt)
            
            except RuntimeError as e:
                if str(e) == 'Property already saved for object':
                    pass
                
            except Exception as e:
                logging.error("Error saving property: %s", str(e))
                exception_type, value, tb = sys.exc_info()
                traceback_str = ''.join(traceback.format_tb(tb))
                logging.warning(traceback_str)
                logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                logging.warning(traceback_str)


            
    def unique(self):
        unique_set = set(self.uniqueobjlist)  # Use a set to ensure uniqueness
    
        #search_cache = {}
        
        for x in unique_set:
            #sobjname + "cast" + str(self.sqlcobobj)+"|"+self.sqlcobobj.get_name()+"|"+self.sqlcobobj.get_fullname())
            
            temp_x = x

            obj_fullname = x.split("|")[2]
            objname = x.split("|")[1]
            x = x.split("|")[0]
            x = x.replace('castObject', ',').replace('castFile', ',').replace('(', '').replace(')', '')

            # Split the string once and reuse the result
            parts = x.split(',')
            if len(parts) < 3:  # Ensure there are enough parts in the split result
                logging.warning("Invalid format in x: " + str(x))
                continue
            
            dbtype = parts[0].strip()
            #objname = parts[1].strip()
            objtype = parts[2].strip()
            
            #if '.' in objname:
            #    objname = objname.split('.')[-1]
    
            # replaced by self.search_cache that is filled one time at the beginning to improve performance
            """
            if objname not in search_cache:
                # Perform the search and cache the result
                MethodObjectReferences = list(self.application.search_objects(name=objname, load_properties=True))
                search_cache[objname] = MethodObjectReferences
            else:
                MethodObjectReferences = search_cache[objname]
                         
            # Search objects in the application (make sure search_objects is optimized in your code)
            MethodObjectReferences = list(self.application.search_objects(name=objname, load_properties=True))
            """
            MethodObjectReferences = self.search_cache.get(objname) 
            
            if MethodObjectReferences:
                for obj in MethodObjectReferences:
                    if obj.get_type() == objtype and obj.get_fullname() == obj_fullname:
                        try:
                            # Using the optimized count method
                            cnt = str(self.unique_obj_count[temp_x])   # Use list.count instead of custom countcastobject function
                            obj.save_property('dboraclemigrationScript.' + dbtype, cnt)
                            #logging.info("Property saved: ---> dboraclemigrationScript." + dbtype + " in obj " + str(obj.get_name()) + " " + cnt)
                        
                        except KeyError:
                            cnt = '0'
                        except RuntimeError as e:
                            if str(e) == 'Property already saved for object':
                                pass
                            
                        except Exception as e:
                            logging.error("Error saving property: %s", str(e))
                            exception_type, value, tb = sys.exc_info()
                            traceback_str = ''.join(traceback.format_tb(tb))
                            logging.warning(traceback_str)
                            logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                            logging.warning(traceback_str)

    def countcastobject(self, lst, x):
        count = 0
        for ele in lst:
            if (ele == x):
                count = count + 1
        return count
         
        
        
            
    def setprop(self, file, sobjname, rulename,type='None'):
            # one RF for multiples patterns
            
            rfCall = ReferenceFinder()
            rfCall.add_pattern(('srcline'),before ='' , element =self.sregex, after = '')     
            cntprop = 0
            # search all patterns in current program
            try:
#                 self.propvalue =[]
                getvalue=""
                cntprop= 0
                references = [reference for reference in rfCall.find_references_in_file(file)]
                for  reference in references:
                    #reference.bookmark.file= file
                    temp_ref_obj = reference.object
                    cntprop =cntprop+1
                    if type != 'None':
                        #self.propvalue.append(str(reference.value)+" "+str(reference.bookmark))
                        file.save_violation('dboraclemigration_CustomMetrics.'+ rulename, reference.bookmark)
                        logging.debug("violation saved: >" +'dboraclemigration_CustomMetrics.'+rulename+"  line:::"+str(reference.value)+str(reference.bookmark))
                    elif type == 'shell':
                        temp_bookmark = reference.bookmark
                        temp_bookmark_begin_line = temp_bookmark.begin_line+1
                        temp_bookmark_end_line = temp_bookmark.end_line+1
                        temp_bookmark_begin_column = temp_bookmark.begin_column
                        temp_bookmark_end_column = temp_bookmark.end_column
                        final_bookmark = Bookmark(file,temp_bookmark_begin_line,temp_bookmark_begin_column,temp_bookmark_end_line,temp_bookmark_end_column)
                        file.save_violation('dboraclemigration_CustomMetrics.'+ rulename, final_bookmark)
                        logging.debug("violation saved: >" +'dboraclemigration_CustomMetrics.'+rulename+"  line:::"+str(reference.value)+str(final_bookmark))

                            #break
#                     file.save_property('dboraclemigrationScript.'+sobjname, reference.value+" "+str(reference.bookmark) )
#                     logging.info("property saved: >" +'dboraclemigrationScript.'+sobjname +" "+str(reference.bookmark)+ ' '+ str(reference.value))
                getvalue=str(cntprop)
                #logging.info("Value of list-->"+ str(getvalue))
                if cntprop >0:
                    file.save_property('dboraclemigrationScript.'+sobjname, getvalue)
                    logging.debug("property saved: --->" +'dboraclemigrationScript.'+sobjname +" "+getvalue)
               
#       
            except Exception as e:
                logging.info(": error  saving property violation on properties  : %s", str(e))  
                exception_type, value, tb = sys.exc_info()
                traceback_str = ''.join(traceback.format_tb(tb))
                logging.warning(traceback_str)
                logging.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
                logging.warning(traceback_str)
                return 
            
