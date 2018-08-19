// Freddy the Serial(isation) Killer
//
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Base class for all payload classes.
 *
 * Written by Steven van der Baan (@vdbaan).
 **********************************************************/
public class Payload {
    //Payload data
    byte[] _payloadBytes;

    public Payload() {}

    public Payload(byte[] bytes) {
        _payloadBytes = bytes;
    }

    /*******************
     * Get the payload bybts.
     *
     * @return The payload bytes.
     ******************/
    public byte[] getPayloadBytes() {
        return _payloadBytes;
    }
}
