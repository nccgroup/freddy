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
 * Module targeting the XML handling functionality of the
 * .NET FSPickler library.
 * 
 * Note that exploitation requires the target application
 * to deserialize a data type that can contain a payload
 * object in a property.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FSPicklerXmlModule extends FreddyModuleBase {
	protected void initialiseModule() {
		setName("FSPickler (XML)");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(false);
		setDescriptionCaveats("Note that exploitation relies on injecting a payload into an appropriate " +
				"member/property in the object graph (e.g. a property of type 'Object').");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator(Pattern.compile("((<)|(%3c)|(%3C))FsPickler"), IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("FsPickler.XmlPickleReader", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<?xml version=\"1.0\" encoding=\"utf-8\"?><FsPickler version=\"4.0.0.0\" type=\"\"></FsPickler>", "FsPickler.XmlPickleReader");
	}
}
