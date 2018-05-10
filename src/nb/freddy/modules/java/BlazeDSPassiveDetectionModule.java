// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Passive detection module for BlazeDS.
 * 
 * This replaces the passive scan checks in the three
 * BlazeDS modules which check for the same exception type
 * in responses. Using this module only one issue is
 * reported rather than three.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BlazeDSPassiveDetectionModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("BlazeDS-AMF");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		registerPassiveScanIndicator("flex.messaging.MessageException", IndicatorTarget.RESPONSE);
	}
}
