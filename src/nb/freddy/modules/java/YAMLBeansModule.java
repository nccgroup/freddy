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
 * Module targeting the Java YAMLBeans library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class YAMLBeansModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("YAMLBeans");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator("com.esotericsoftware.yamlbeans.YamlException", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("'", "com.esotericsoftware.yamlbeans.YamlException");
	}
}
