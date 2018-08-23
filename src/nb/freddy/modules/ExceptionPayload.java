// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import java.util.ArrayList;
import java.util.regex.Pattern;

/***********************************************************
 * Wrapper for an exception-based active scan payload and
 * a scan indicator that indicates success.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ExceptionPayload extends Payload {


    //Exception-based success indicator
    private final ScanIndicator _indicator;

    /*******************
     * Initialise a payload wrapper with a string indicator.
     *
     * @param payloadBytes The payload that should trigger an exception when deserialized.
     * @param successIndicator A string that should appear in the exception if the application displays exceptions.
     ******************/
    public ExceptionPayload(byte[] payloadBytes, String successIndicator) {
        _payloadBytes = payloadBytes;
        _indicator = new ScanIndicator(successIndicator);
    }

    /*******************
     * Initialise a payload wrapper with a regex indicator.
     *
     * @param payloadBytes The payload that should trigger an exception when deserialized.
     * @param successIndicator A regular expression that can be used to detect the resulting exception.
     ******************/
    public ExceptionPayload(byte[] payloadBytes, Pattern successIndicator) {
        _payloadBytes = payloadBytes;
        _indicator = new ScanIndicator(successIndicator);
    }

    /*******************
     * Search for the success indicator in a HTTP response string.
     *
     * @param responseStr The HTTP response to search.
     * @return A list of int pairs marking the start and end indices of all instances of the indicator.
     ******************/
    public ArrayList<int[]> findIndicator(String responseStr) {
        return _indicator.findInstances(responseStr);
    }
}
