// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Issue confidence enum.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public enum ConfidenceRating {
	CERTAIN("Certain"),
	FIRM("Firm"),
	TENTATIVE("Tentative");
	
	//Confidence string
	private final String _confidence;
	
	/*******************
	 * Construct from string.
	 * 
	 * @param confidence The confidence string.
	 ******************/
	private ConfidenceRating(String confidence) {
		_confidence = confidence;
	}
	
	/*******************
	 * Convert confidence value to string.
	 * 
	 * @return The string representation of the enum value.
	 ******************/
	public String toString() {
		return _confidence;
	}
}
