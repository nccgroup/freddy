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
import java.util.ArrayList;
import java.util.List;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.Payload;

/***********************************************************
 * Burp Intruder payload generator which generates payloads
 * that should indicate whether the target is vulnerable to
 * remote command execution via deserialization.
 * 
 * These payloads should trigger a range of effects such
 * as:
 *  -> Triggering a Win32Exception (.NET/Mono)
 *  -> Triggering a time delay
 *  -> Triggering a collaborator interaction
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RCEPayloadGenerator implements IIntruderPayloadGenerator {
	/*******************
	 * Properties
	 ******************/
	private ArrayList<Payload> _payloads;
	private int _currentIndex;
	
	/*******************
	 * Construct a new payload generator instance.
	 * 
	 * @param modules A list of loaded Freddy modules.
	 ******************/
	public RCEPayloadGenerator(ArrayList<FreddyModuleBase> modules, IIntruderAttack attack) {
		List<Payload> modPayloads;
		
		//Generate a list of all RCE detection payloads
		_payloads = new ArrayList<>();
		for(FreddyModuleBase module: modules) {
			modPayloads = module.getRCEPayloads(attack);
			if(modPayloads != null) {
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
		Payload payload = _payloads.get(_currentIndex);
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


