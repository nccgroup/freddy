// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IIntruderAttack;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import nb.freddy.FreddyIssue;

/***********************************************************
 * Base class for Freddy scanner modules.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class FreddyModule {
	/*******************
	 * Constants
	 ******************/
	protected static final Pattern PAT_EXCEPTION = buildPattern("Exception");
	protected static final Pattern PAT_W32EXCEPTION = buildPattern("Win32Exception");
	
	/*******************
	 * Properties
	 ******************/
	protected IBurpExtenderCallbacks _callbacks;
	protected SecureRandom _rng = new SecureRandom();
	private IBurpCollaboratorClientContext _collabContext;
	private ArrayList<CollabRecord> _collabPayloads;
	
	/*******************
	 * Initialise the module.
	 * 
	 * @param callbacks The Burp callbacks object.
	 * @param collabContext The Burp Collaborator client context object.
	 ******************/
	public final void initialise(IBurpExtenderCallbacks callbacks, IBurpCollaboratorClientContext collabContext) {
		_callbacks = callbacks;
		_collabContext = collabContext;
		_collabPayloads = new ArrayList<CollabRecord>();
	}
	
	/*******************
	 * Delegate passive scanning to the abstract doPassiveScan method.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @return A list of identified issues or null if no issues were identified.
	 ******************/
	public final List<IScanIssue> passiveScan(IHttpRequestResponse baseRequestResponse) {
		//Run a passive scan
		return doPassiveScan(baseRequestResponse);
	}
	
	/*******************
	 * Subclasses implement this method to perform passive scanning.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @return A list of identified issues or null if no issues were identified.
	 ******************/
	protected abstract List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse);
	
	/*******************
	 * Delegate active scanning to the abstract doActiveScan method.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @param insertionPoint The insertion point to test against.
	 * @return A list of identified issues or null if no issues were identified.
	 ******************/
	public final List<IScanIssue> activeScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		//Run an active scan
		return doActiveScan(baseRequestResponse, insertionPoint);
	}
	
	/*******************
	 * Subclasses implement this method to perform active scanning.
	 * 
	 * @param baseRequestResponse The HTTP request and response to scan.
	 * @param insertionPoint The insertion point to test against.
	 * @return A list of identified issues or null if no issues were identified.
	 ******************/
	protected abstract List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);
	
	/*******************
	 * Construct a regular expression pattern to match the given string in a
	 * request or response body.
	 * 
	 * This method ensures that the regular expressions used by the module to
	 * detect type specifiers and exceptions can also detect matches that use
	 * URL or HTML encoding, for example the following JSON type specifier:
	 * 
	 *   "$type"
	 * 
	 * Might be encoded as the following:
	 * 
	 *   %22%24type%22
	 *   &quot;$type&quot;
	 *   &QUOT;$type&QUOT;
	 * 
	 * All of which will be matched by the generated regular expression.
	 * 
	 * @param match The string to match.
	 * @return A regular expression pattern to match the string with various encodings.
	 ******************/
	protected static final Pattern buildPattern(String match) {
		String finalPattern;
		
		//Escape "."
		finalPattern = match.replace(".", "\\.");
		
		//Match double quotes
		finalPattern = finalPattern.replace("\"", "((\")|(%22)|(&quot;))");
		
		//Escape curly braces
		finalPattern = finalPattern.replace("{", "\\{");
		finalPattern = finalPattern.replace("}", "\\}");
		
		//Match colon
		finalPattern = finalPattern.replace(":", "((:)|(%3a)|(&#3a;))");
		
		//Match semi-colon
		finalPattern = finalPattern.replace(";", "((;)|(&#59;))");
		
		//Match the dollar symbol
		finalPattern = finalPattern.replace("$", "((\\$)|(%24))");
		
		//Match the greater-than and less-than symbols
		finalPattern = finalPattern.replace("<", "((<)|(%3c)|(&lt;))");
		finalPattern = finalPattern.replace(">", "((>)|(%3e)|(&gt;))");
		
		//Match the equals symbol
		finalPattern = finalPattern.replace("=", "((=)|(%3d))");
		
		//Match question marks
		finalPattern = finalPattern.replace("?", "((\\?)|(%3f))");
		
		//Match forward slashes
		finalPattern = finalPattern.replace("/", "((\\/)|(%2f))");
		
		//Match the @ symbol
		finalPattern = finalPattern.replace("@", "((@)|(%40))");
		
		//Match single quotes
		finalPattern = finalPattern.replace("'", "((')|(%27)|(&apos;)|(&#39;))");
		
		//Match spaces and allow multiple consecutive spaces in the resulting regex
		finalPattern = finalPattern.replace(" ", "(( )|(\\+)|(%20)|(&nbsp;))+");
		
		//Return the compiled pattern
		return Pattern.compile(finalPattern, Pattern.CASE_INSENSITIVE);
	}
	
	/*******************
	 * Helper method to generate a random invalid command name to aid in
	 * detecting command execution vulnerabilities.
	 * 
	 * @return A random string to use in an RCE payload.
	 ******************/
	protected String generateInvalidRandomCommandName() {
		return "freddy" + _rng.nextLong() + "" + _rng.nextLong();
	}
	
	/*******************
	 * Search for and return all instances matching a given pattern within the
	 * given string.
	 * 
	 * @param pattern Regex pattern to search with.
	 * @param haystack The string to search within.
	 * @return A list of pairs of integers indicating the start/end of results.
	 ******************/
	protected final List<int[]> findInstancesOfPattern(Pattern pattern, String haystack) {
		List<int[]> matches = new ArrayList<int[]>();
		Matcher matcher;
		
		//Find all matches
		matcher = pattern.matcher(haystack);
		while(matcher.find()) {
			matches.add(new int[] {matcher.start(), matcher.end()});
		}
		
		//Return all matches
		return matches;
	}
	
	/*******************
	 * Wrapper for findInstancesOfPattern(String, String) that converts a byte
	 * array to a string before searching.
	 * 
	 * @param pattern Regex pattern to search with.
	 * @param haystack The string to search within.
	 * @return A list of pairs of integers indicating the start/end of results.
	 ******************/
	protected final List<int[]> findInstancesOfPattern(Pattern pattern, byte[] haystack) {
		//TODO
		//Test this with _callbacks.getHelpers().bytesToString(haystack)
		//Prefer the helpers method if it works as expected.
		return findInstancesOfPattern(pattern, new String(haystack));
	}
	
	/*******************
	 * Helper method to generate a new Freddy issue.
	 * 
	 * @param issueName The issue-specific name/title.
	 * @param issueDetail The issue-specific detail.
	 * @param remediationDetail The issue-specific remediation details.
	 * @param severity The severity of this issue.
	 * @param confidence The confidence of this issue.
	 * @param messages The relevant HTTP messages.
	 * @return A FreddyIssue object.
	 ******************/
	protected final FreddyIssue createIssue(String issueName, String issueDetail, String remediationDetail, String severity, String confidence, IHttpRequestResponse[] messages) {
		return new FreddyIssue(
				issueName,
				_callbacks.getHelpers().analyzeRequest(messages[0]).getUrl(),
				messages[0].getHttpService(),
				messages,
				severity,
				confidence,
				issueDetail,
				remediationDetail
		);
	}
	
	/*******************
	 * Helper method to generate a new Freddy issue for collaborator
	 * interactions generated by Burp Intruder payloads.
	 * 
	 * @param issueName The issue-specific name/title.
	 * @param issueDetail The issue-specific detail.
	 * @param remediationDetail The issue-specific remediation details.
	 * @param severity The severity of this issue.
	 * @param confidence The confidence of this issue.
	 * @param service The HTTP service for which the issue was generated.
	 * @param request The base Intruder request body.
	 * @return A FreddyIssue object.
	 ******************/
	protected final FreddyIssue createIntruderCollaboratorIssue(String issueName, String issueDetail, String remediationDetail, String severity, String confidence, IHttpService service, byte[] request) {
		return new FreddyIssue(
				issueName,
				_callbacks.getHelpers().analyzeRequest(request).getUrl(),
				service,
				null,
				severity,
				confidence,
				issueDetail,
				remediationDetail
		);
	}
	
	/*******************
	 * Combine two lists of markers so that they are in ascending order of
	 * starting offset and there are no overlaps.
	 * 
	 * @param list1 The first list.
	 * @param list2 The second list.
	 * @return A new list with markers in order.
	 ******************/
	protected List<int[]> combineMarkers(List<int[]> list1, List<int[]> list2) {
		List<int[]> newList;
		List<int[]> noOverlaps;
		
		//Create the new list
		newList = new ArrayList<int[]>();
		newList.addAll(list1);
		newList.addAll(list2);
		
		//Sort the list of markers
		Collections.sort(newList, MarkerListComparator.getInstance());
		
		//Remove any overlapping markers
		noOverlaps = new ArrayList<int[]>();
		noOverlaps.add(newList.get(0));
		newList.remove(0);
		while(newList.size() > 0) {
			//Check if the current marker starts after the last one ended
			if(newList.get(0)[0] > noOverlaps.get(noOverlaps.size() - 1)[1]) {
				//Keep the current marker
				noOverlaps.add(newList.get(0));
				newList.remove(0);
			} else {
				//Set the end of the previous marker to the end of this marker
				noOverlaps.get(noOverlaps.size() - 1)[1] = newList.get(0)[1];
				newList.remove(0);
			}
		}
		
		//Return the list of markers without overlaps
		return noOverlaps;
	}
	
	/*******************
	 * Generate a collaborator payload, storing a copy so that interactions can
	 * be handled.
	 * 
	 * @param reqRes The HTTP messages that triggered the interaction.
	 * @return A collaborator payload in the form of a domain name.
	 ******************/
	protected final String getCollaboratorPayload(IHttpRequestResponse[] reqRes) {
		String payload;
		
		//Get and log a payload
		payload = _collabContext.generatePayload(false);
		_collabPayloads.add(new CollabRecord(payload, reqRes));
		
		//Return the payload
		return payload + "." + _collabContext.getCollaboratorServerLocation();
	}
	
	/*******************
	 * Generate a collaborator payload to use with a Burp Intruder payload
	 * generator.
	 * 
	 * @param service The targeted HTTP service.
	 * @param request The base request used in Intruder.
	 * @return A collaborator payload in the form of a domain name.
	 ******************/
	protected final String getIntruderCollaboratorPayload(IHttpService service, byte[] request) {
		String payload;
		
		//Get and log a payload
		payload = _collabContext.generatePayload(false);
		_collabPayloads.add(new CollabRecord(payload, service, request));
		
		//Return the payload
		return payload + "." + _collabContext.getCollaboratorServerLocation();
	}
	
	/*******************
	 * Handle Collaborator interactions by delegating to the method
	 * reportCollaboratorInteraction() or
	 * reportIntruderCollaboratorInteraction() if the interaction ID was
	 * generated by this module.
	 * 
	 * @param interaction The Burp Collaborator interaction.
	 * @return True if the interaction is handled by this module.
	 ******************/
	public final boolean handleCollaboratorInteraction(IBurpCollaboratorInteraction interaction) {
		String interactionId;
		
		//Check if the interaction ID was generated by this module
		interactionId = interaction.getProperty("interaction_id");
		for(CollabRecord record: _collabPayloads) {
			if(record.getPayload().equals(interactionId)) {
				//Handle the collaborator interaction
				if(record.getMessages() != null) {
					reportCollaboratorInteraction(interaction, record.getMessages());
				} else {
					reportIntruderCollaboratorInteraction(interaction, record.getService(), record.getRequest());
				}
				return true;
			}
		}
		
		//Collaborator ID was not generated by this module
		return false;
	}
	
	/*******************
	 * Subclasses override this method to report issues based on Burp
	 * collaborator interactions.
	 * 
	 * @param interaction The Burp collaborator interaction.
	 * @param reqRes The HTTP messages that triggered the interaction.
	 ******************/
	protected void reportCollaboratorInteraction(IBurpCollaboratorInteraction interaction, IHttpRequestResponse[] reqRes) {
		//This implementation shouldn't be triggered
		_callbacks.printError("FreddyModule::reportCollaboratorInteraction() called. The class " + getClass().getSimpleName() + " should override this method to handle the collaborator interaction.");
	}
	
	/*******************
	 * Subclasses override this method to report issues based on Burp
	 * collaborator interactions that were the result of payloads generated for
	 * Burp Intruder.
	 * 
	 * @param interaction The Burp collaborator interaction.
	 * @param service The HTTP service targeted by Intruder.
	 * @param request The HTTP request targeted by Intruder.
	 ******************/
	protected void reportIntruderCollaboratorInteraction(IBurpCollaboratorInteraction interaction, IHttpService service, byte[] request) {
		//This implementation shouldn't be triggered
		_callbacks.printError("FreddyModule::reportIntruderCollaboratorInteraction() called. The class " + getClass().getSimpleName() + " should override this method to handle the collaborator interaction.");
	}
	
	/*******************
	 * Subclasses override this method to provide a list of error-based
	 * payloads for use with Burp Intruder.
	 * 
	 * @return A list of payloads that may trigger errors to reveal the target deserialization library.
	 ******************/
	public abstract List<byte[]> getErrorBasedPayloads();
	
	/*******************
	 * Subclasses override this method to provide a list of payloads for use
	 * with Burp Intruder to help detect when an application is vulnerable to
	 * remote command execution via deserialization.
	 * 
	 * @param attack The Intruder attack data, used to build a request to map collaborator issues to.
	 * @return A list of payloads that may reveal RCE vulnerabilities or null if there are no such payloads.
	 ******************/
	public List<byte[]> getRCEPayloads(IIntruderAttack attack) {
		//Not all modules have RCE payloads so default implementation returns null
		return null;
	}
}
