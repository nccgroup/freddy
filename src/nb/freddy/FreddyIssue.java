// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import java.net.URL;

/***********************************************************
 * Burp scanner issue for issues identified by Freddy
 * modules.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FreddyIssue implements IScanIssue {
	private final String _name;
	private final URL _url;
	private final IHttpService _httpService;
	private final IHttpRequestResponse[] _httpMessages;
	private final String _severity;
	private final String _confidence;
	private final String _detail;
	private final String _remediationDetail;
	
	/*******************
	 * Construct a new FreddyIssue with all necessary details.
	 * 
	 * @param name The issue name/title.
	 * @param url The URL where the issue was identified.
	 * @param service The HTTP service used to identify the issue.
	 * @param messages Relevant HTTP messages.
	 * @param severity The issue severity.
	 * @param confidence The issue confidence.
	 * @param detail Specific details of this this issue.
	 * @param remediationDetail Specific remediation guidelines for this issue.
	 ******************/
	public FreddyIssue(String name, URL url, IHttpService service, IHttpRequestResponse[] messages, String severity, String confidence, String detail, String remediationDetail) {
		_name = name;
		_url = url;
		_httpService = service;
		_httpMessages = messages;
		_severity = severity;
		_confidence = confidence;
		_detail = detail;
		_remediationDetail = remediationDetail;
	}
	
	/*******************
	 * Getters
	 ******************/
	public URL getUrl() { return _url; }
	public String getIssueName() { return _name; }
	public int getIssueType() { return 0x08000000; }
	public String getSeverity() { return _severity; }
	public String getConfidence() { return _confidence; }
	public String getIssueDetail() { return _detail; }
	public String getRemediationDetail() { return _remediationDetail; }
	public IHttpRequestResponse[] getHttpMessages() { return _httpMessages; }
	public IHttpService getHttpService() { return _httpService; }
	public String getIssueBackground() {
		return "The application appears to make use of a JSON or XML library " +
			   "to deserialize runtime objects. If an an attacker can supply " +
			   "arbitrary data to be deserialized then they may be able to " +
			   "cause arbitrary runtime objects to be created whilst " +
			   "controlling the properties of those objects. Using these " +
			   "object properties it may be possible to manipulate the flow " +
			   "of execution of certain sections of application code (known " +
			   "as POP gadgets) to the attacker's advantage.\n" +
			   "The actual impact varies greatly depending on the code that " +
			   "can be manipulated, however there are known POP gadgets in " +
			   "both native APIs and common third-party libraries that can " +
			   "be manipulated to achieve arbitrary code or operating system " +
			   "command execution.";
	}
	public String getRemediationBackground() {
		return "Where possible the JSON or XML data should be rejected if " +
			   "type specifiers (e.g. the class of object to deserialize) " +
			   "are included in the data, in order to prevent an attacker " +
			   "from selecting the type of object to deserialize.\n" +
			   "Where type specifiers are required, the specified type " +
			   "should be validated against a strict <strong>whitelist" +
			   "</strong> of known classes that the application is expected " +
			   "to deserialize in order to limit the code that an attacker " +
			   "can manipulate through deserialization.\n" +
			   "Whitelists should be kept minimal and be as restrictive as " +
			   "possible in order to limit the scope for attack. At the very " +
			   "least, a whitelist must not allow arbitrary objects, that is " +
			   "java.lang.Object and System.Object must not be included on " +
			   "whitelist. In addition, generic collection types and classes " +
			   "with properties of these types should also be rejected.";
	}
}
