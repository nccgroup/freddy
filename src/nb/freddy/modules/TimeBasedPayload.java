// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Wrapper for a time-based active scan payload.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class TimeBasedPayload extends Payload {

	private final long _delay;
	
	/*******************
	 * Initialise a time based payload wrapper.
	 * 
	 * @param payloadBytes The payload that should trigger a time delay (e.g. ping command).
	 * @param delay An indication as to the time delay that should be induced using this payload.
	 ******************/
	public TimeBasedPayload(byte[] payloadBytes, long delay) {
		_payloadBytes = payloadBytes;
		_delay = delay;
	}

	
	/*******************
	 * Get the length of the time delay induced by this payload.
	 * 
	 * @return The time delay induced by this payload.
	 ******************/
	public long getTimeDelay() {
		return _delay;
	}
}
