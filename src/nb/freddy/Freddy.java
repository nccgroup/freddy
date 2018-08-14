// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import java.util.ArrayList;
import java.util.List;

import nb.freddy.intruder.ErrorPayloadGeneratorFactory;
import nb.freddy.intruder.RCEPayloadGeneratorFactory;
import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.dotnet.BinaryFormatterModule;
import nb.freddy.modules.dotnet.DataContractJsonSerializerModule;
import nb.freddy.modules.dotnet.DataContractSerializerModule;
import nb.freddy.modules.dotnet.FSPicklerJsonModule;
import nb.freddy.modules.dotnet.FSPicklerXmlModule;
import nb.freddy.modules.dotnet.FastJsonModule;
import nb.freddy.modules.dotnet.JavascriptSerializerModule;
import nb.freddy.modules.dotnet.JsonDotNetModule;
import nb.freddy.modules.dotnet.NetDataContractSerializerModule;
import nb.freddy.modules.dotnet.ObjectStateFormatterModule;
import nb.freddy.modules.dotnet.SoapFormatterModule;
import nb.freddy.modules.dotnet.SweetJaysonModule;
import nb.freddy.modules.dotnet.XmlSerializerModule;
import nb.freddy.modules.java.BlazeDSAMF0Module;
import nb.freddy.modules.java.BlazeDSAMF3Module;
import nb.freddy.modules.java.BlazeDSAMFXModule;
import nb.freddy.modules.java.BlazeDSPassiveDetectionModule;
import nb.freddy.modules.java.BurlapModule;
import nb.freddy.modules.java.CastorModule;
import nb.freddy.modules.java.FlexJsonModule;
import nb.freddy.modules.java.GensonModule;
import nb.freddy.modules.java.HessianModule;
import nb.freddy.modules.java.JYAMLModule;
import nb.freddy.modules.java.JacksonModule;
import nb.freddy.modules.java.JsonIoModule;
import nb.freddy.modules.java.KryoAltStrategyModule;
import nb.freddy.modules.java.KryoModule;
import nb.freddy.modules.java.KryoPassiveDetectionModule;
import nb.freddy.modules.java.ObjectInputStreamModule;
import nb.freddy.modules.java.Red5AMF0Module;
import nb.freddy.modules.java.Red5AMF3Module;
import nb.freddy.modules.java.SnakeYAMLModule;
import nb.freddy.modules.java.XStreamModule;
import nb.freddy.modules.java.XmlDecoderModule;
import nb.freddy.modules.java.YAMLBeansModule;

/***********************************************************
 * Freddy the serial(isation) killer.
 ***********************************************************
 * Burp Suite extension based on the work of Alvaro Muñoz
 * (@pwntester) and Oleksandr Mirosh which they presented
 * at Black Hat USA 2017 and Def Con 25.
 *  - https://www.blackhat.com/us-17/briefings.html#friday-the-13th-json-attacks
 * 
 * Alvaro and Oleksandr looked at various JSON and XML
 * serialization libraries and found that many of them can
 * be abused to execute deserialization/object injection
 * attacks in the same way as native serialization APIs
 * such as those found in Java and PHP.
 * 
 * Further payloads and targets were implemented in
 * version 2.0 based on ysoserial.NET (Alvaro Muñoz) and
 * the paper "Java Unmarshaller Security - Turning your
 * data into code execution" by Moritz Bechler.
 *  - https://github.com/mbechler/marshalsec/
 *  - https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true
 * 
 * This Burp Suite extension performs active and passive
 * detection of various serialization libraries/APIs.
 ***********************************************************
 * Version Notes
 * 2.0 Revamped release (04/04/2018)
 *  -> Rewrote module architecture to standardise and simplify module
 *     implementation. Majority of scanner module logic is now found in the
 *     FreddyModuleBase class and the modules themselves simply register
 *     indicators and generate payloads.
 *  -> Optimisations have been introduced so that, as much as possible, data is
 *     only generated once and used multiple times. Previously, for example, a
 *     request would be converted from a byte array to a string for every scan
 *     check. Now the Freddy class generates this string once and passes it to
 *     each module for searching.
 *  -> Support for more targets has been added as follows:
 *       BinaryFormatter (.NET native API)
 *       DataContractSerializer (.NET native API)
 *       LosFormatter (.NET native API that uses ObjectStateFormatter under the hood)
 *       NetDataContractSerializer (.NET native API)
 *       ObjectStateFormatter (.NET native API)
 *       SoapFormatter (.NET native API)
 *       XmlSerializer (.NET native API)
 *       BlazeDS AMF 0 (Java 3rd party)
 *       BlazeDS AMF 3 (Java 3rd party)
 *       BlazeDS AMF X (Java 3rd party)
 *       Burlap (Java 3rd party)
 *       Castor (Java 3rd party)
 *       Hessian (Java 3rd party)
 *       JYAML (Java 3rd party)
 *       Kryo (Java 3rd party)
 *       Kryo (Java 3rd party - alternative deserialization strategy)
 *       ObjectInputStream (Java native API)
 *       Red5 AMF 0 (Java 3rd party)
 *       Red5 AMF 3 (Java 3rd party)
 *       Snake YAML (Java 3rd party)
 *       XmlDecoder (Java native API)
 *       XStream (Java 3rd party)
 *       YAMLBeans (Java 3rd party)
 *  -> Support for additional payloads has been added.
 * 
 * 1.0 Initial release (23/01/2018)
 *  -> Passively detects the use of the following serialization libraries/APIs
 *     through the JSON/XML type specifier field in a request or exceptions in
 *     responses:
 *       DataContractJsonSerializer (.NET native API)
 *       FastJson (.NET 3rd party)
 *       FSPickler - JSON format (.NET 3rd party)
 *       FSPickler - XML format (.NET 3rd party)
 *       JavascriptSerializer (.NET native APIE)
 *       Json.Net (.NET 3rd party)
 *       Sweet.Jayson (.NET 3rd party)
 *       FlexJson (Java 3rd party)
 *       Genson (Java 3rd party)
 *       Jackson (Java 3rd party)
 *       JSON-IO (Java 3rd party)
 *  -> Actively detects the use of each of the above using error-based
 *     payloads.
 *  -> Where possible, time-based and collaborator-based payloads are also used
 *     for active detection.
 *       DataContractJsonSerializer
 *       FastJson
 *       JavascriptSerializer
 *       Json.Net
 *       Jackson
 *  -> Burp Intruder payload generators for manual testing.
 ***********************************************************
 * Module/Payload status
 * ----------------------
 * .NET payloads
 * --------------
 * All tested and working apart from PSObject payloads which only work against
 * systems not patched for CVE-2017-8565.
 * 
 * 
 * Java payloads
 * --------------
 * All passive scanner checks and exception-based active scanner checks are
 * tested and working. Various collaborator payloads have not been confirmed
 * working as of version 2.0 (4th April 2018).
 * 
 * The following list details the status of each. Tests were performed using a
 * demo web application and failures don't necessarily indicate a problem with
 * Freddy but instead may be the result of the demo app configuration (e.g. JDK
 * version, setup/usage of target library etc). Some payloads may also need to
 * be injected into a property of another object in the serialized data.
 * 
 * BlazeDSAMF0
 * -> C3P0WrapperConnPool appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> SpringPropertyPathFactory appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * 
 * BlazeDSAMF3
 * -> C3P0WrapperConnPool appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> SpringPropertyPathFactory appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * 
 * BlazeDSAMFX
 * -> C3P0WrapperConnPool has been tested and confirmed working
 * -> SpringPropertyPathFactory appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * 
 * Burlap
 * -> Resin triggered an exception when deserialized (java.io.IOException: java.lang.InstantiationException: javax.naming.spi.ContinuationDirContext)
 * -> Rome has been tested and confirmed working
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * -> SpringPartiallyComparableAdvisor has been tested and confirmed working
 * -> XBean has been tested and confirmed working
 * 
 * Castor
 * -> C3P0WrapperConnPool has been tested and confirmed working
 * -> SpringPropertyPathFactory has been tested and confirmed working
 * 
 * Hessian
 * -> Resin has been tested and confirmed working
 * -> Rome has been tested and confirmed working
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * -> SpringPartiallyComparableAdvisor has been tested and confirmed working
 * -> XBean has been tested and confirmed working
 * 
 * Jackson
 * -> C3P0RefDataSource has been tested and confirmed working
 * -> C3P0WrapperConnPool has been tested and confirmed working
 * -> JdbcRowSet triggered an exception when deserialized (com.fasterxml.jackson.databind.JsonMappingException: Conflicting setter definitions for property "matchColumn": com.sun.rowset.JdbcRowSetImpl#setMatchColumn(1 params) vs com.sun.rowset.JdbcRowSetImpl#setMatchColumn(1 params))
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * -> SpringPropertyPathFactory has been tested and confirmed working
 * -> Templates has been tested and confirmed working
 * 
 * JSON-IO
 * -> Groovy has been tested and confirmed working
 * -> LazySearchEnumeration has been tested and confirmed working
 * -> Resin triggered an exception when deserialized (java.io.IOException: Class 'java.lang.Object' requested for special instantiation - isPrimitive() does not match newPrimitiveWrapper())
 * -> Rome appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> SpringAbstractBeanFactory triggered an exception when deserialized (org.springframework.beans.factory.NoSuchBeanDefinitionException: No bean named 'caller' available)
 * -> XBean has been tested and confirmed working
 * 
 * JYAML
 * -> C3P0RefDataSource has been tested and confirmed working
 * -> C3P0WrapperConnPool has been tested and confirmed working
 * -> JdbcRowSet has been tested and confirmed working
 * 
 * Kryo
 * -> CommonsBeanutils has been tested and confirmed working
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * 
 * KryoAltStrategy
 * -> CommonsBeanutils has been tested and confirmed working
 * -> ImageIO triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): jdk.nashorn.internal.objects.NativeString)
 * -> LazySearchEnumeration triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): jdk.nashorn.internal.objects.NativeString)
 * -> Resin triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): com.caucho.naming.QName)
 * -> Rome triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): com.rometools.rome.feed.impl.EqualsBean)
 * -> SpringAbstractBeanFactory triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): java.lang.ProcessBuilder)
 * -> SpringPartiallyComparableAdvisor triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): org.springframework.aop.target.HotSwappableTargetSource)
 * -> XBean triggered an exception when deserialized (com.esotericsoftware.kryo.KryoException: Class cannot be created (missing no-arg constructor): org.springframework.aop.target.HotSwappableTargetSource)
 * 
 * ObjectInputStream
 * -> CommonsBeanutils has been tested and confirmed working
 * -> XBean has been tested and confirmed working
 * 
 * Red5AMF0
 * -> C3P0WrapperConnPool appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> JdbcRowSet has been tested and confirmed working
 * -> SpringPropertyPathFactory appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * 
 * Red5AMF3
 * -> C3P0WrapperConnPool appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> JdbcRowSet has been tested and confirmed working
 * -> SpringPropertyPathFactory appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * 
 * SnakeYAML
 * -> C3P0RefDataSource has been tested and confirmed working
 * -> CommonsConfiguration has been tested and confirmed working
 * -> JdbcRowSet has been tested and confirmed working
 * -> ResourceGadget triggered an exception when deserialized (Can't construct a java object for tag:yaml.org,2002:org.eclipse.jetty.plus.jndi.Resource; exception=java.lang.reflect.InvocationTargetException)
 * -> ScriptEngine has been tested and confirmed working
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * -> SpringPropertyPathFactory has been tested and confirmed working
 * -> XBean has been tested and confirmed working
 * 
 * XStream
 * -> CommonsBeanutils has been tested and confirmed working
 * -> ImageIO has been tested and confirmed working
 * -> LazySearchEnumeration has been tested and confirmed working
 * -> Resin appeared to deserialize in demo lab but didn't trigger collaborator interaction
 * -> Rome has been tested and confirmed working
 * -> SpringAbstractBeanFactory has been tested and confirmed working
 * -> SpringParticallyComparableAdvisor has been tested and confirmed working
 * -> XBean has been tested and confirmed working
 ***********************************************************
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class Freddy implements IScannerCheck, IExtensionStateListener {
	//Constants
	private static final String EXTENSION_NAME = "Freddy";
	private static final float EXTENSION_VERSION = 2.1f;
	private static final String[] IGNORE_EXTENSIONS = {".css", ".js", ".jpg", ".jpeg", ".gif", ".png", ".svg", ".ico"};
	
	//Burp objects
	private IBurpExtenderCallbacks _callbacks;
	private IExtensionHelpers _helpers;
	private IBurpCollaboratorClientContext _collabContext;
	
	//Collaborator polling thread
	private FreddyCollaboratorThread _freddyCollaborator;
	
	//Freddy scanner modules
	private ArrayList<FreddyModuleBase> _modules;
	
	/*******************
	 * Load all available Freddy modules.
	 ******************/
	public Freddy() {
		_modules = new ArrayList<FreddyModuleBase>();
		
		//.NET modules
		_modules.add(new BinaryFormatterModule());
		_modules.add(new DataContractJsonSerializerModule());
		_modules.add(new DataContractSerializerModule());
		_modules.add(new FSPicklerJsonModule());
		_modules.add(new FSPicklerXmlModule());
		_modules.add(new FastJsonModule());
		_modules.add(new JavascriptSerializerModule());
		_modules.add(new JsonDotNetModule());
		_modules.add(new NetDataContractSerializerModule());
		_modules.add(new ObjectStateFormatterModule());
		_modules.add(new SoapFormatterModule());
		_modules.add(new SweetJaysonModule());
		_modules.add(new XmlSerializerModule());
		
		//Java modules
		_modules.add(new BlazeDSAMF0Module());
		_modules.add(new BlazeDSAMF3Module());
		_modules.add(new BlazeDSAMFXModule());
		_modules.add(new BlazeDSPassiveDetectionModule());
		_modules.add(new BurlapModule());
		_modules.add(new CastorModule());
		_modules.add(new FlexJsonModule());
		_modules.add(new GensonModule());
		_modules.add(new HessianModule());
		_modules.add(new JacksonModule());
		_modules.add(new JsonIoModule());
		_modules.add(new JYAMLModule());
		_modules.add(new KryoModule());
		_modules.add(new KryoAltStrategyModule());
		_modules.add(new KryoPassiveDetectionModule());
		_modules.add(new ObjectInputStreamModule());
		_modules.add(new Red5AMF0Module());
		_modules.add(new Red5AMF3Module());
		_modules.add(new SnakeYAMLModule());
		_modules.add(new XmlDecoderModule());
		_modules.add(new XStreamModule());
		_modules.add(new YAMLBeansModule());
	}
	
	/*******************
	 * Initialise the extension, initialise all modules, and start the
	 * collaborator polling thread.
	 * 
	 * @param callbacks The IBurpExtenderCallbacks object from Burp Suite.
	 ******************/
	public void initialise(IBurpExtenderCallbacks callbacks) {
		_callbacks = callbacks;
		_helpers = _callbacks.getHelpers();
		_collabContext = _callbacks.createBurpCollaboratorClientContext();
		_callbacks.setExtensionName(EXTENSION_NAME + " v" + EXTENSION_VERSION);
		_callbacks.registerScannerCheck(this);
		_callbacks.registerExtensionStateListener(this);
		
		//Pass the Burp extender callbacks and the collaborator client context to all loaded modules
		for(FreddyModuleBase module: _modules) {
			module.initialise(_callbacks, _collabContext);
		}
		
		//Register payload generator factories
		_callbacks.registerIntruderPayloadGeneratorFactory(new ErrorPayloadGeneratorFactory(_modules));
//		_callbacks.registerIntruderPayloadGeneratorFactory(new RCEPayloadGeneratorFactory(_modules));
		
		//Start the Collaborator polling thread
		_freddyCollaborator = new FreddyCollaboratorThread(_collabContext, _modules);
		_freddyCollaborator.start();
	}
	
	/*******************
	 * Passively scan the given request and response pair.
	 * 
	 * Ignores CSS, JS, and image URLs and passes requests for all others to
	 * all loaded modules for passive scanning.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @return A list of identified issues or null if no issues were identified.
	 ******************/
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		List<IScanIssue> issues = null;
		List<IScanIssue> moduleIssues;
		String requestStr;
		String responseStr;
		String urlPath;
		
		//Ignore CSS, JS, and images
		urlPath = _helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().toLowerCase();
		for(String ext: IGNORE_EXTENSIONS) {
			if(urlPath.endsWith(ext)) {
				return null;
			}
		}
		
		//Build the request and response strings ready to pass to the individual modules
		requestStr = _callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest());
		responseStr = _callbacks.getHelpers().bytesToString(baseRequestResponse.getResponse());
		
		//Run all module passive scans
		for(FreddyModuleBase module: _modules) {
			//Run the scan
			moduleIssues = module.doPassiveScan(baseRequestResponse, requestStr, responseStr);
			
			//If there were results, add them to the full list of results
			if(moduleIssues != null && moduleIssues.size() > 0) {
				//Create the full list of results if it hasn't already been created
				if(issues == null) {
					issues = new ArrayList<IScanIssue>();
				}
				issues.addAll(moduleIssues);
			}
		}
		
		//Return the identified issues (null if none identified)
		return issues;
	}
	
	/*******************
	 * Perform an active scan - delegates scanning work to all loaded Freddy
	 * modules.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @param insertionPoint An insertion point used for building new requests.
	 * @return A list of identified issues or null if no issues are identified.
	 ******************/
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		List<IScanIssue> issues = null;
		List<IScanIssue> moduleIssues;
		String urlPath;
		
		//Ignore CSS, JS, and images
		urlPath = _helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().toLowerCase();
		for(String ext: IGNORE_EXTENSIONS) {
			if(urlPath.endsWith(ext)) {
				return null;
			}
		}
		
		//Run all module active scans
		for(FreddyModuleBase module: _modules) {
			//Run the scan
			moduleIssues = module.doActiveScan(baseRequestResponse, insertionPoint);
			
			//If there were results, add them to the full list of results
			if(moduleIssues != null && moduleIssues.size() > 0) {
				//Create the full list of results if it hasn't already been created
				if(issues == null) {
					issues = new ArrayList<IScanIssue>();
				}
				issues.addAll(moduleIssues);
			}
		}
		
		//Return the identified issues
		return issues;
	}
	
	/*******************
	 * Consolidate duplicate issues.
	 * 
	 * @param existingIssue The existing scanner issue.
	 * @param newIssue The new scanner issue.
	 * @return -1 keep existing issue, 0 to keep both, 1 to keep the new issue.
	 ******************/
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		//Compare issues
		if(existingIssue.getUrl().equals(newIssue.getUrl()) && existingIssue.getIssueName().equals(newIssue.getIssueName())) {
			//Return the issue with higher confidence
			if(confidenceValue(existingIssue) > confidenceValue(newIssue)) {
				return -1;
			} else if(confidenceValue(existingIssue) < confidenceValue(newIssue)) {
				return 1;
			} else {
				//Confidence matches, return the issue with higher severity
				if(severityValue(existingIssue) > severityValue(newIssue)) {
					return -1;
				} else if(severityValue(existingIssue) < severityValue(newIssue)) {
					return 1;
				} else {
					//Both match, keep the existing issue
					return -1;
				}
			}
		}
		
		//Keep both issues
		return 0;
	}
	
	/*******************
	 * Map an issue confidence to an integer value where higher values
	 * represent greater confidence.
	 * 
	 * @param issue The Burp issue containing the confidence level..
	 * @return An integer representation of the confidence value.
	 ******************/
	private int confidenceValue(IScanIssue issue) {
		if(issue.getConfidence().equals("Certain")) { return 2; }
		if(issue.getConfidence().equals("Firm")) { return 1; }
		if(issue.getConfidence().equals("Tentative")) { return 0; }
		
		//Invalid value supplied
		_callbacks.printError("Bad confidence value: \"" + issue.getConfidence() + "\".");
		return -1;
	}
	
	/*******************
	 * Map an issue severity to an integer value where higher values represent
	 * greater severity.
	 * 
	 * @param issue The Burp issue containing the severity level.
	 * @return An integer representation of the severity value.
	 ******************/
	private int severityValue(IScanIssue issue) {
		if(issue.getSeverity().equals("High")) { return 4; }
		if(issue.getSeverity().equals("Medium")) { return 3; }
		if(issue.getSeverity().equals("Low")) { return 2; }
		if(issue.getSeverity().equals("Information")) { return 1; }
		if(issue.getSeverity().equals("False positive")) { return 0; }
		
		//Invalid value supplied
		_callbacks.printError("Bad severity value: \"" + issue.getSeverity() + "\".");
		return -1;
	}
	
	/*******************
	 * Stop the background collaborator polling thread when the extension is
	 * unloaded.
	 ******************/
	public void extensionUnloaded() {
		_freddyCollaborator.stopCollaborating();
	}
}
