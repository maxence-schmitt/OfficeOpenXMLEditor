from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab

import json
import tempfile
import os
import re
from UpdateableZipFile import UpdateableZipFile
import multipart as mp
try:
    from io import BytesIO as IO
except ImportError:
    from StringIO import StringIO as IO
from array import array
from zipfile import ZipFile, ZIP_STORED, ZipInfo

	
			

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):


    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Office Open XML Editor")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        return
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return OfficeOpenXMLInputTab(self, controller, editable)

# 
# class implementing IMessageEditorTab
#
class OfficeOpenXMLInputTab(IMessageEditorTab):

    #Parsing multipart request do verify Content-Type of parameter inside multipart/form-data
    def parseMultipart(self,request):
        reqInfo = self._extender._helpers.analyzeRequest(request)
        if reqInfo.getMethod() == "POST" and reqInfo.getContentType() == reqInfo.CONTENT_TYPE_MULTIPART:
                #Going thru headers to find Content-Type header
                headers = reqInfo.getHeaders()
                for header in headers:
                    #Reading boundary
                    res = re.search(r'Content-Type: multipart/.*; boundary=(.*)', header)
                    if res != None :
                        boundary = res.group(1)
                        try:
                            env = {'REQUEST_METHOD': 'POST','CONTENT_TYPE': 'multipart/form-data; boundary='+boundary,'wsgi.input': IO(request[reqInfo.getBodyOffset():])}
                            rforms, rfiles = mp.parse_form_data(env, strict=True, charset='utf8')
                            for files in rfiles:
                                for file in rfiles.getall(files):
                                    print "file:"+file.name+":"+file.content_type
                                    if file.content_type in self._listOfOOXMLContentType:
                                        parameter = self._extender._helpers.getRequestParameter(request, file.name)

                                        #Saving zip content and the span where the zip is
                                        self._zip = parameter.getValue()
                                        self._valueStart = parameter.getValueStart()
                                        self._valueEnd = parameter.getValueEnd()

                                        print "OOXML Document detected in the following parameter:" + file.name

                                        break;
                        except Exception as e:
                            print("Error: {0}".format(e))
 
    def readConfig(self):
        file_name = os.getcwd() + os.sep + "conf" + os.sep + "conf.json"
        with open(file_name) as data_file:
            data = json.load(data_file)
            self._listOfOOXMLContentType = data["Content-Types"]
            self._fileToOpen = data["FileToOpen"]
            self._tryToFindZip = data["tryToFindZip"]
            print "Extension enabled for following Content-Types:" + str(self._listOfOOXMLContentType)
            print "File to open in OOXML:" + self._fileToOpen
            print "tryToFindZip value:" + str(self._tryToFindZip)

    def __init__(self, extender, controller, editable):
        try:
            self._tryToFindZip = False
            self.readConfig()
            self._extender = extender
            self._editable = editable
            self._content = ""
            self._tempName = ""
            self._txtInput = extender._callbacks.createTextEditor()
            self._txtInput.setEditable(editable)
            self._zip = None
            self._valueStart = 0
            self._valueEnd = 0
        except Exception as e:
            print("Error: {0}".format(e))
        return
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Office Open XML Editor"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        if isRequest :
            #Try to find parameter with good content-Type in multipart/form
            self.parseMultipart(content)
            if self._zip is not None:
                return True

            #If tryTofindZip enabled
            else :
                if self._tryToFindZip is True:
                    try:
                        #Try to find zip with this regex
                        m = re.search(r"^.+\n(PK.+)\r\n.+$", content, re.MULTILINE|re.DOTALL)
                        if m :
                            print 'ZIP detected'

                            #Saving zip content and the span where the zip is
                            self._zip = m.group(1)
                            self._valueStart = m.start(1)
                            self._valueEnd = m.end(1)

                            return True
                        return False
                    except Exception as e:
                        print("Error: {0}".format(e))
        return False

    def setMessage(self, content, isRequest):
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            try:
                #Creating temporary file
                with tempfile.NamedTemporaryFile('wb',delete=False) as temp:
                    temp.write(self._extender._helpers.stringToBytes(self._zip))
                    self._tempName=temp.name

                #Reading the file inside zip
                with ZipFile(self._tempName,'r') as myzip:
                    data = myzip.read(self._fileToOpen)

                self._txtInput.setText(data)
                self._txtInput.setEditable(self._editable)
                self._content=content
            except Exception as e:
                print("Error: {0}".format(e))
		
        return
    
    def getMessage(self):
        # determine whether the user modified data
        if (self._txtInput.isTextModified()):
            try:
                #Modifying content with the input of the tab
                with UpdateableZipFile(self._tempName, 'a') as o:
                    o.writestr(self._fileToOpen, self._txtInput.getText())

                #Reading the modified document
                with open(self._tempName, mode='rb') as file: 
                    modifiedContent = file.read()

                #reading Request data in order to rebuild it
                request=self._extender._helpers.analyzeRequest(self._content)
                headers=request.getHeaders()

                #Replacing with new zip
                self._content[self._valueStart:self._valueEnd]=array('b',modifiedContent)

                #Reinitialize value
                self._zip = None
                self._valueStart = 0
                self._valueEnd = 0

                #Rebuild request(calculate Content-length)
                return self._extender._helpers.buildHttpMessage(headers,self._content[request.getBodyOffset():])
                
            except Exception as e:
                print("Error: {0}".format(e))
    
        else:
            return self._content
    
    def isModified(self):
        
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        
        return self._txtInput.getSelectedText()
            
