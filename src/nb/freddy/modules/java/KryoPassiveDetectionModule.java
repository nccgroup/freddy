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
 * Passive detection module for Kryo.
 * 
 * This replaces the passive scan checks in the Kryo and
 * KryoAltStrategy modules which both check for the same
 * exception type in responses.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class KryoPassiveDetectionModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("Kryo");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		registerPassiveScanIndicator("com.esotericsoftware.kryo.KryoException", IndicatorTarget.RESPONSE);
	}
}
