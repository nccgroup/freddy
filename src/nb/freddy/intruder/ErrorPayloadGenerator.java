// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.intruder;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import nb.freddy.modules.ExceptionPayload;
import nb.freddy.modules.FreddyModuleBase;

import java.util.ArrayList;
import java.util.List;

/***********************************************************
 * Burp Intruder payload generator which generates payloads
 * that trigger errors or exceptions when parsed by
 * affected parsers in order to aid manual detection of
 * vulnerable applications.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ErrorPayloadGenerator implements IIntruderPayloadGenerator {
    /*******************
     * Properties
     ******************/
    private ArrayList<ExceptionPayload> _payloads;
    private int _currentIndex;

    /*******************
     * Construct a new payload generator instance.
     *
     * @param modules A list of loaded Freddy modules.
     ******************/
    public ErrorPayloadGenerator(ArrayList<FreddyModuleBase> modules, IIntruderAttack attack) {
        List<ExceptionPayload> modPayloads;

        //Generate a list of all error-based payloads
        _payloads = new ArrayList<>();
        for (FreddyModuleBase module : modules) {
            modPayloads = module.getErrorBasedPayloads();
            if (modPayloads != null) {
                _payloads.addAll(modPayloads);
            }
        }

        //Start at the first payload
        _currentIndex = 0;
    }

    /*******************
     * Check if there are any more payloads available.
     *
     * @return True if there are more payloads available.
     ******************/
    public boolean hasMorePayloads() {
        return _currentIndex < _payloads.size();
    }

    /*******************
     * Get the next payload.
     *
     * @param baseValue The base value from the Intruder injection point.
     * @return The bytes of the next payload.
     ******************/
    public byte[] getNextPayload(byte[] baseValue) {
        ExceptionPayload payload = _payloads.get(_currentIndex);
        _currentIndex += 1;
        return payload.getPayloadBytes();
    }

    /*******************
     * Reset the payload generator.
     ******************/
    public void reset() {
        _currentIndex = 0;
    }
}
