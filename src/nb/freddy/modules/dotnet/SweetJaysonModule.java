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
 * Module targeting the .NET Sweet.Jayson library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class SweetJaysonModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("Sweet.Jayson");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))type((\")|(%22))"), IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("Sweet.Jayson.JaysonConverter", IndicatorTarget.RESPONSE);
		
		//Register false positive so passive scan issues don't fire for FastJson
		registerPassiveScanFalsePositiveIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))types((\")|(%22))"), IndicatorTarget.REQUEST);
		
		registerActiveScanExceptionPayload("{\"$type\":\"", "Sweet.Jayson.JaysonConverter");
	}
}
