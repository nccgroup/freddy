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

import java.util.regex.Pattern;

/***********************************************************
 * Module targeting the Java FlexJson library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FlexJsonModule extends FreddyModuleBase {
    protected void initialiseModule() {
        setName("FlexJson");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(false);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.MEDIUM);

        registerPassiveScanIndicator(Pattern.compile("((\")|(%22))class((\")|(%22))"), IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("flexjson.JSONException", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("{\"class\":\"\"}", "flexjson.JSONException");
    }
}
