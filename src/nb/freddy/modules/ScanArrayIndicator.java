// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.regex.Pattern;

/***********************************************************
 * Extension of the ScanIndicator class to support the
 * detection of multiple values such that all of the values
 * must be detected in order to return any indicator
 * offsets.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ScanArrayIndicator extends ScanIndicator {
	//Indicator data
	private final Pattern[] _indicatorRegexs;
	
	/*******************
	 * Create an indicator to search for multiple regex patterns.
	 * 
	 * @param searchPatterns The regex patterns to search for.
	 ******************/
	public ScanArrayIndicator(Pattern[] searchPatterns) {
		if(searchPatterns.length < 2) {
			throw new IllegalArgumentException("ScanArrayIndicator(Pattern[]) must be called with more than one Pattern object, otherwise a ScanIndicator should be used.");
		}
		_indicatorRegexs = searchPatterns;
	}
	
	/*******************
	 * Check whether the indicator is text-based and hence operates on a string
	 * rather than raw bytes.
	 * 
	 * ATM only regex arrays are supported so all are text based.
	 * 
	 * @return True if the indicator is text-based.
	 ******************/
	public boolean isTextBased() {
		return true;
	}
	
	/*******************
	 * Find all instances of text-based indicator values in the given string
	 * but only return a list of instances if all indicators are found in the
	 * given string.
	 * 
	 * @param targetStr The string to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicators, provided all indicators were found.
	 ******************/
	public ArrayList<int[]> findInstances(String targetStr) {
		ArrayList<ArrayList<int[]>> matches = new ArrayList<ArrayList<int[]>>();
		ArrayList<int[]> allMatches;
		
		//Bail if not a text-based indicator
		if(isTextBased() == false) {
			throw new IllegalStateException("ScanArrayIndicator.findInstances(String) called on a byte-based indicator.");
		}
		
		//Find all matches
		for(Pattern pat: _indicatorRegexs) {
			allMatches = findRegexMatches(pat, targetStr);
			if(allMatches != null && allMatches.size() > 0) {
				matches.add(allMatches);
			}
		}
		
		//Return all matches, sorted and with all overlaps merged, if all patterns were matched
		if(matches.size() == _indicatorRegexs.length) {
			allMatches = combineMarkerSets(matches.remove(0), matches.remove(0));
			while(matches.size() > 1) {
				allMatches = combineMarkerSets(allMatches, matches.remove(0));
			}
			return allMatches;
		} else {
			return null;
		}
	}
	
	/*******************
	 * Combine two sets of markers into one set that's sorted by starting
	 * offset where overlapping markers are merged.
	 * 
	 * @param list1 The first list of markers.
	 * @param list2 The second list of markers.
	 * @return A new sorted list with overlaps merged.
	 ******************/
	private ArrayList<int[]> combineMarkerSets(ArrayList<int[]> list1, ArrayList<int[]> list2) {
		ArrayList<int[]> newList;
		ArrayList<int[]> noOverlaps;
		
		//Create the new list
		newList = new ArrayList<int[]>();
		newList.addAll(list1);
		newList.addAll(list2);
		
		//Sort the list of markers
		Collections.sort(newList, MarkerListComparator.getInstance());
		
		//Remove any overlapping markers
		noOverlaps = new ArrayList<int[]>();
		noOverlaps.add(newList.get(0));
		newList.remove(0);
		while(newList.size() > 0) {
			//Check if the current marker starts after the last one ended
			if(newList.get(0)[0] > noOverlaps.get(noOverlaps.size() - 1)[1]) {
				//Keep the current marker
				noOverlaps.add(newList.get(0));
				newList.remove(0);
			} else {
				//Set the end of the previous marker to the end of this marker
				noOverlaps.get(noOverlaps.size() - 1)[1] = newList.get(0)[1];
				newList.remove(0);
			}
		}
		
		//Return the list of markers without overlaps
		return noOverlaps;
	}
}
