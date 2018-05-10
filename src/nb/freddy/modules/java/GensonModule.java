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
 * Module targeting the Java Genson library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class GensonModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("Genson");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator(Pattern.compile("((\")|(%22))((@)|(%40))class((\")|(%22))"), IndicatorTarget.REQUEST);
		registerPassiveScanIndicator(new Pattern[] { Pattern.compile("com\\.owlike\\.genson\\."), Pattern.compile("exception", Pattern.CASE_INSENSITIVE) } , IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("{\"@class\":\"\"}", "genson.JsonBindingException");
	}
}
