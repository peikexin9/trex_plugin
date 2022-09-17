package trex;

import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class TrexPopupMenu extends ListingContextAction {
	public final String MenuName = "TrexPlugin";
    public final String Group_Name = "SymEx";
    static Address CurrentAddr;
    static List < Address > CurrentFunctionAddress0 = new ArrayList<Address>();
    static List < Address > CurrentFunctionAddress1 = new ArrayList<Address>();
    public static PluginTool tool;
    public static Program program;
    private FunctionManager functionManager;
    
    
    public TrexPopupMenu(TrexPlugin plugin, TrexPluginProvider TrexProvider, Program program) {
        super("TrexPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupAction(TrexProvider);
    }
    
    public void setProgram(Program p) {
        program = p;
    }
    
    public void setupAction(TrexPluginProvider TrexProvider) {
    	tool.setMenuGroup(new String[] {
                MenuName
            }, Group_Name);
    	
    	ListingContextAction Parse0 = new ListingContextAction("parse function", getName()) {
    		
    		@Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentFunctionAddress0 != null) {
                    UnSetColor(CurrentFunctionAddress0);
                }
                functionManager = program.getFunctionManager();
                Address address = context.getLocation().getAddress();
                Function function = functionManager.getFunctionContaining(address);
                Address entry_point = function.getEntryPoint();
                Address addr = function.getEntryPoint();
                while (functionManager.getFunctionContaining(addr) == function) {
                	SetColor(addr, Color.CYAN);
                	CurrentFunctionAddress0.add(addr);
                    addr = addr.next();
    			}
                SetColor(address, Color.CYAN);
                try {
					TrexProvider.FunctionParsing(function, entry_point, addr, "input0", program);
				} catch (Exception e) {
					e.printStackTrace();
				}
            }
        };
        
        Parse0.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Load to input0",
        }, null, Group_Name));
        tool.addAction(Parse0);
        
        ListingContextAction Parse1 = new ListingContextAction("parse function", getName()) {
    		
    		@Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentFunctionAddress1 != null) {
                    UnSetColor(CurrentFunctionAddress1);
                }
                functionManager = program.getFunctionManager();
                Address address = context.getLocation().getAddress();
                Function function = functionManager.getFunctionContaining(address);
                Address entry_point = function.getEntryPoint();
                Address addr = function.getEntryPoint();
                while (functionManager.getFunctionContaining(addr) == function) {
                	SetColor(addr, Color.RED);
                	CurrentFunctionAddress1.add(addr);
                    addr = addr.next();
    			}
                SetColor(address, Color.RED);
                try {
					TrexProvider.FunctionParsing(function, entry_point, addr, "input1", program);
				} catch (Exception e) {
					e.printStackTrace();
				}
            }
        };
        
        Parse1.setPopupMenuData(new MenuData(new String[] {
                MenuName,
                "Load to input1",
        }, null, Group_Name));
        tool.addAction(Parse1);
        
        ListingContextAction RunScript = new ListingContextAction("Run Script", getName()) {
        	
        	@Override
            protected void actionPerformed(ListingActionContext context) {
        		
            	try {
            		String spath=null;
                	spath = new File(TrexPluginProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
                	ProcessBuilder pb = new ProcessBuilder(spath.substring(0, spath.indexOf("lib"))+"ghidra_scripts/c++");
    	            Process p = pb.start();
    	            p.waitFor();
                	String line = null;
        			BufferedReader reader = new BufferedReader(new FileReader(spath.substring(0, spath.indexOf("lib"))+"data/result/similarity.csv"));
        			if ((line=reader.readLine())!=null) {
        				String item[] = line.split(",");
        				Output output = new Output();
        		        output.printSimilarity("Similarity: " + item[0]);
;        			}
        		} catch (Exception e) {
        			e.printStackTrace();
        		}
        	}
        };
        
        RunScript.setPopupMenuData(new MenuData(new String[] {
                MenuName,
                "Run Similarity",
        }, null, Group_Name));
        tool.addAction(RunScript);
    }
    
	public static void UnSetColor(List < Address > addresses) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        for (Address address : addresses) {
        	service.clearBackgroundColor(address, address);
        }
        program.endTransaction(TransactionID, true);

    }

    public static void SetColor(Address address, Color color) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);

    }
    
}