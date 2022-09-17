package trex;

import ghidra.app.script.GhidraScript;

public class Output extends GhidraScript {

	public void printSimilarity(String similarity) {
		popup(similarity);
	}

	@Override
	protected void run() throws Exception {}
}