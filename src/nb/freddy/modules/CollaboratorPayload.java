// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Wrapper for a Burp Collaborator active scan payload.
 *
 * Unlike exception and time-based payloads, which can be
 * generated in advance, this class does not contain the
 * actual payload data. Instead this class contains a
 * unique name (per payload per module) that is used to
 * refer to the payload and a flag indicating whether the
 * payload is binary or text.
 *
 * To generate payloads, Freddy will pass the payload name
 * to individual modules along with the unique Collaborator
 * ID (hostname) to use in the generated payload. In the
 * case of binary payloads Freddy will generate a second
 * payload and base 64 encode it in order to cover both
 * possibilities and distinguish between the two.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class CollaboratorPayload {
    //Payload data
    private final String _name;
    private final boolean _isBinary;

    /*******************
     * Initialise a Collaborator payload wrapper.
     *
     * @param name A unique name for the payload.
     * @param isBinary True if the payload is binary as opposed to text-based.
     ******************/
    public CollaboratorPayload(String name, boolean isBinary) {
        _name = name;
        _isBinary = isBinary;
    }

    /*******************
     * Get the payload name.
     *
     * @return The payload name.
     ******************/
    public String getPayloadName() {
        return _name;
    }

    /*******************
     * Get the flag indicating whether the payload is binary or text.
     *
     * @return True if the payload is a binary one, false if it is text.
     ******************/
    public boolean isBinary() {
        return _isBinary;
    }
}
