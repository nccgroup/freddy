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
 * Module targeting the JSON handling functionality of the
 * .NET FSPickler library.
 * 
 * Note that exploitation requires the target application
 * to deserialize a data type that can contain a payload
 * object in a property.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FSPicklerJsonModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("FSPickler (JSON)");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("Note that exploitation relies on injecting a payload into an appropriate " +
				"member/property in the object graph (e.g. a property of type 'Object').");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator(new Pattern[] { Pattern.compile("((\")|(%22))FsPickler((\")|(%22))"), Pattern.compile("((\")|(%22))type((\")|(%22))") }, IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("FsPickler.Json", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("{\"FsPickler\":\"4.0.0\",\"type\":\"\"}", "FsPickler.Json");
	}
}
