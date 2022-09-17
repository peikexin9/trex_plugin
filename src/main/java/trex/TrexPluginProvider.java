package trex;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ListSelectionModel;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.json.JSONException;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.list.ListPanel;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.app.plugin.core.datamgr.util.*;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.app.util.*;
import ghidra.program.model.symbol.Reference;

public class TrexPluginProvider extends ComponentProvider {

		private JPanel panel;
		private JPanel EndPanel;
		private static Program program;
		private FunctionManager functionManager;
		private Memory memory;
		private JButton btnRun;
	    private JButton btnLoad;
	    private static Function input0_func;
	    private static Function input1_func;
	    private JPanel SimilarityResult;
	    private Program[] thisAllPrograms;
	    TrexPlugin Plugin;

		public TrexPluginProvider(TrexPlugin plugin, String owner, Program Program) {
	        super(plugin.getTool(), owner, owner);
	        Plugin = plugin;
	        setProgram(Program);
	        buildPanel();
	    }

		// Customize GUI
		private void buildPanel() {
			
			panel = new JPanel(new BorderLayout());
			panel.setMinimumSize(new Dimension(210, 510));
			setVisible(true);
			
	        JPanel input0Panel = new JPanel();
	        TitledBorder borderinput0 = BorderFactory.createTitledBorder("Fisrt Input");
	        borderinput0.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
	        input0Panel.setBorder(borderinput0);

	        JPanel input1Panel = new JPanel();
	        TitledBorder borderinput1 = BorderFactory.createTitledBorder("Second Input");
	        borderinput1.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
	        input1Panel.setBorder(borderinput1);

	        btnLoad = new JButton("Load");
	        btnLoad.setFont(new Font("SansSerif", Font.PLAIN, 12));
			
			btnLoad.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					input0Panel.removeAll();
					input1Panel.removeAll();
					thisAllPrograms = Plugin.getTool().getService(ProgramManager.class).getAllOpenPrograms();
					for (Program nowprogram: thisAllPrograms) {
						functionManager = nowprogram.getFunctionManager();
						
						FunctionIterator func_ite = functionManager.getFunctionsNoStubs(true);
						Function func = func_ite.next();
						
						DefaultListModel<Function> listModel = new DefaultListModel<>();
						while (func != null) {
							listModel.addElement(func);
							func = func_ite.next();
						}
						
						ListPanel listPanel0 = new ListPanel();
						listPanel0.setName("input_0");
						listPanel0.setListModel(listModel);
						listPanel0.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
						listPanel0.setSelectedIndex(0);
						listPanel0.setListSelectionListener(new ListSelectionListener() {
							@Override
							public void valueChanged(ListSelectionEvent e) {
								input0_func = (Function) listPanel0.getSelectedValue();
				                Address entry_point = input0_func.getEntryPoint();
				                Address addr = input0_func.getEntryPoint();
				                while (functionManager.getFunctionContaining(addr) == input0_func) {
				                    addr = addr.next();
				    			}
				                try {
									FunctionParsing(input0_func, entry_point, addr, "input0", nowprogram);
								} catch (Exception e0) {
									e0.printStackTrace();
								}
							}
						});
						
						ListPanel listPanel1 = new ListPanel();
						listPanel1.setName("input_1");
						listPanel1.setListModel(listModel);
						listPanel1.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
						listPanel1.setSelectedIndex(0);
						listPanel1.setListSelectionListener(new ListSelectionListener() {
							@Override
							public void valueChanged(ListSelectionEvent e1) {
								input1_func = (Function) listPanel1.getSelectedValue();
								Address entry_point = input1_func.getEntryPoint();
				                Address addr = input1_func.getEntryPoint();
				                while (functionManager.getFunctionContaining(addr) == input1_func) {
				                    addr = addr.next();
				    			}
				                try {
									FunctionParsing(input1_func, entry_point, addr, "input1", nowprogram);
								} catch (Exception e11) {
									e11.printStackTrace();
								}
							}
						});
						
						input0Panel.add(new JScrollPane(listPanel0));
						input1Panel.add(new JScrollPane(listPanel1));
					}
					panel.repaint();
	                panel.revalidate();
				}
			});
			
			EndPanel = new JPanel();
	        EndPanel.setBorder(null);

	        btnRun = new JButton("Run");
	        btnRun.setFont(new Font("SansSerif", Font.PLAIN, 12));
	        btnRun.addActionListener(new ActionListener() {
	        	public void actionPerformed(ActionEvent e) {
	                try {
	                	//StartPython("trex");
	                	String spath=null;
	                	spath = new File(TrexPluginProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
	                	ProcessBuilder pb = new ProcessBuilder(spath.substring(0, spath.indexOf("lib"))+"ghidra_scripts/c++");
        	            Process p = pb.start();
        	            p.waitFor();
	                	String line = null;
		                BufferedReader reader = new BufferedReader(new FileReader(spath.substring(0, spath.indexOf("lib"))+"data/result/similarity.csv"));
						if ((line=reader.readLine())!=null) {
							String item[] = line.split(",");
							JTextArea similarityText = new JTextArea("Similarity: " + item[0]);
					        similarityText.setFont(new Font("SansSerif", Font.PLAIN, 12));
					        similarityText.setEditable(false);
					        SimilarityResult.removeAll();
					        SimilarityResult.add(similarityText);
						    panel.repaint();
						    panel.revalidate();
						}
						reader.close();
					} catch (Exception e1) {
						e1.printStackTrace();
					}
	        	}
	        });

	        SimilarityResult = new JPanel();
	        TitledBorder borderresult = BorderFactory.createTitledBorder("Result");
	        borderresult.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
	        SimilarityResult.setBorder(borderresult);
	        
	        GroupLayout gl_EndPanel = new GroupLayout(EndPanel);
	        gl_EndPanel.setHorizontalGroup(
	        	gl_EndPanel.createParallelGroup(Alignment.LEADING)
	        		.addGroup(gl_EndPanel.createSequentialGroup()
	        			.addGroup(gl_EndPanel.createParallelGroup(Alignment.TRAILING)
	        				.addGroup(gl_EndPanel.createSequentialGroup()
	        					.addGap(134)
	        					.addComponent(btnLoad, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
	        					.addGap(77)
	        					.addComponent(btnRun, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
	        					.addGap(62)))
	        			.addGap(91))
	        		.addComponent(SimilarityResult, GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE)
	        );
	        gl_EndPanel.setVerticalGroup(
	        	gl_EndPanel.createParallelGroup(Alignment.LEADING)
		        	.addGroup(gl_EndPanel.createSequentialGroup()
		        		.addGroup(gl_EndPanel.createParallelGroup(Alignment.LEADING)
		        			.addGroup(gl_EndPanel.createSequentialGroup()
		        				.addContainerGap()
		        				.addComponent(btnLoad, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
		        			.addGroup(gl_EndPanel.createSequentialGroup()
		        				.addContainerGap()
		        				.addComponent(btnRun, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)))
		        		.addPreferredGap(ComponentPlacement.RELATED)
			        	.addComponent(SimilarityResult, GroupLayout.DEFAULT_SIZE, 13, Short.MAX_VALUE))
	        );
	        EndPanel.setLayout(gl_EndPanel);
			
			GroupLayout gl_panel = new GroupLayout(panel);
	        gl_panel.setHorizontalGroup(
	            gl_panel.createParallelGroup(Alignment.TRAILING)
	            .addGroup(gl_panel.createSequentialGroup()
	                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
	                    .addGroup(gl_panel.createSequentialGroup()
	                        .addContainerGap()
	                        .addComponent(EndPanel, GroupLayout.DEFAULT_SIZE, 550, Short.MAX_VALUE))
	                    .addGroup(gl_panel.createSequentialGroup()
	                        .addGap(10)
	                        .addComponent(input0Panel, GroupLayout.DEFAULT_SIZE, 15, Short.MAX_VALUE)
	                        .addPreferredGap(ComponentPlacement.RELATED)
	                        .addComponent(input1Panel, GroupLayout.DEFAULT_SIZE, 15, Short.MAX_VALUE)))
	                .addGap(13))
	        );
	        gl_panel.setVerticalGroup(
	            gl_panel.createParallelGroup(Alignment.LEADING)
	            .addGroup(gl_panel.createSequentialGroup()
	                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
	                    .addGroup(gl_panel.createSequentialGroup()
	                    	.addContainerGap()
	                    	.addComponent(input0Panel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE))
	                    .addGroup(gl_panel.createSequentialGroup()
	                        .addContainerGap()
	                        .addComponent(input1Panel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)))
	                .addPreferredGap(ComponentPlacement.UNRELATED)
	                .addComponent(EndPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
	                .addGap(5))
	        );
			panel.setLayout(gl_panel);
	        
		}	
		
		public static String addZeroForNum(String str, int strLength) {
		    int strLen = str.length();
		    if (strLen < strLength) {
		        while (strLen < strLength) {
		            StringBuffer sb = new StringBuffer();
		            sb.append("0").append(str);
		            str = sb.toString();
		            strLen = str.length();
		        }
		    }
		    return str;
		}
		
		public String get_function_raw_bytes(Function function, Address addr) throws MemoryAccessException {
			List<String> code = new ArrayList<String>();
			while (functionManager.getFunctionContaining(addr) == function) {
				Integer bytes = memory.getByte(addr)&0xff;
				String hex = addZeroForNum(Integer.toHexString(bytes),2);
				code.add(hex);
				addr = addr.next();
			}
			return String.join("\\", code);
		}
		
		@SuppressWarnings("deprecation")
		public JSONObject get_loc_dict(Function function) throws JSONException {
			Variable[] variables = function.getAllVariables();
			JSONObject obj = new JSONObject();
			for (int i=0; i<variables.length; i++) {
				Variable var = variables[i];
				JSONObject subobj = new JSONObject();
				JSONObject agg = new JSONObject();
				String var_name = var.getName().toString();
				DataType data_type = DataTypeUtils.getBaseDataType(var.getDataType());
				if (data_type.toString().indexOf("Structure") != -1) agg.put("is_struct", true);
				else agg.put("is_struct", false);
				if (data_type.toString().indexOf("Union") != -1) agg.put("is_union", true);
				else agg.put("is_union", false);
				if (data_type.toString().indexOf("Enumerate") != -1) agg.put("is_enum", true);
				else agg.put("is_enum", false);
				Register rego = var.getRegister();
				String reg;
				if (rego == null) reg = "Stack[" + Integer.toHexString(var.getStackOffset()) + "]";
				else reg = rego.toString();
				Set<Reference> refs = XReferenceUtil.getVariableRefs(var);
				for(Reference reference : refs) {
					subobj.accumulate("z", reference.getFromAddress().toString());
				}
				subobj.put("count", i);
				subobj.put("type", data_type);
				subobj.put("register", reg);
				subobj.put("agg", agg);
				obj.put(var_name, subobj);
			}
			return obj;
		}
		
		public void FunctionParsing(Function function, Address start_addr, Address end_addr, String method, Program nowprogram) throws Exception {
			
			functionManager = nowprogram.getFunctionManager();
	        memory = nowprogram.getMemory();
	        
	        String spath = null;
            try {
                spath = new File(TrexPluginProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
            } catch (URISyntaxException e2) {
                e2.printStackTrace();
            }
	        
			String code_dir = spath.substring(0, spath.indexOf("lib")) + "data" + File.separator + "function" + File.separator + method + "_code.json";
			String stack_dir = spath.substring(0, spath.indexOf("lib"))+"data" + File.separator + "function" + File.separator + method + "_stack.json";
			
			String code = get_function_raw_bytes(function, start_addr);
			try (FileWriter osw_code = new FileWriter(code_dir)) {
				JSONObject obj_code = new JSONObject();
				JSONObject subobj_code = new JSONObject();
				subobj_code.put("code", code);
				subobj_code.put("start_addr", start_addr.toString());
				subobj_code.put("end_addr", end_addr.toString());
				obj_code.put(function.toString(), subobj_code);
				osw_code.write(obj_code.toString());
				osw_code.flush();
				osw_code.close();
			} catch (IOException e) {
                e.printStackTrace();
            }
			
			try (FileWriter osw_stack = new FileWriter(stack_dir)) {
				JSONObject obj_stack = new JSONObject();
				JSONObject subobj_stack = get_loc_dict(function);
				obj_stack.put(function.toString(), subobj_stack);
				osw_stack.write(obj_stack.toString());
				osw_stack.flush();
				osw_stack.close();
			}
			
			StartPython(method);
		}
		
        public String StartPython(String method) throws Exception {
        	
        	String spath = null;
            try {
                spath = new File(TrexPluginProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
            } catch (URISyntaxException e2) {
                e2.printStackTrace();
            }
            
        	String script_path;
        	if (method == "trex") {
        		script_path = spath.substring(0, spath.indexOf("lib"))+"ghidra_scripts/trex.py";
        	}
        	else {
        		script_path = spath.substring(0, spath.indexOf("lib"))+"ghidra_scripts/ghidra_extract_"+method+".py";
        	}
			
        	
            if (runScript("python3", script_path) == 0) {
    			ProcessBuilder pb = new ProcessBuilder("python", "--version");
           	 	try {
                    Process p = pb.start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line = "";
                    while ((line = reader.readLine()) != null) {                	         	
                    	if (compareVersion(line.substring(7), "3.4") == -1 && compareVersion(line.substring(7), "3.0") == 1) {
                    		runScript("python", script_path);
                    	}    
                    }           
                    p.waitFor();
                    reader.close();
                } catch (Exception e1) {
                    e1.printStackTrace();
                }           
    		}
            return null;
        }

	    public int runScript(String pythonVersion, String script_path) {
	        ProcessBuilder pb = new ProcessBuilder(pythonVersion, script_path);
	        try {
	            Process p = pb.start();
	            p.waitFor();
	            return 1;
	        } catch (Exception e1) {
	            e1.printStackTrace();
	            return 0;
	        }
	    }
	    
	    public int compareVersion(String version1, String version2) {
		    String[] arr1 = version1.split("\\.");
		    String[] arr2 = version2.split("\\.");
		 
		    int i=0;
		    while(i<arr1.length || i<arr2.length){
		        if(i<arr1.length && i<arr2.length){
		            if(Integer.parseInt(arr1[i]) < Integer.parseInt(arr2[i])){
		                return -1;
		            }else if(Integer.parseInt(arr1[i]) > Integer.parseInt(arr2[i])){
		                return 1;
		            }
		        } else if(i<arr1.length){
		            if(Integer.parseInt(arr1[i]) != 0){
		                return 1;
		            }
		        } else if(i<arr2.length){
		           if(Integer.parseInt(arr2[i]) != 0){
		                return -1;
		            }
		        }	 
		        i++;
		    }	 
		    return 0;
		}
	    
	    @Override
	    public JComponent getComponent() {
	        return panel;
	    }
		
		public void setProgram(Program p) {
	        program = p;
	    }
	}