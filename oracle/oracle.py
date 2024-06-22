import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import paths as pt 
sys.path.append(pt.firmsolo_dir)
import custom_utils as cu
from stage2a.kconfiglib import Kconfig, expr_str
from stage2c.get_struct_options import Kernel, get_struct_conditionals
from stage2b.get_order import get_dictionary
import subprocess as sb

mips_options = f"{pt.pandawan_dir}/data/pop_mips_opts.pkl"
arm_options = f"{pt.pandawan_dir}/data/pop_arm_opts.pkl"

class Oracle():
    def __init__(self, image) -> None:
        self.image = image
        self.__categorize_popular_opts()
    
    def __categorize_popular_opts(self):   
        mips_opts = cu.read_pickle(mips_options)   
        arm_opts = cu.read_pickle(arm_options)
        
        self.above_avg_mips = set()
        self.above_avg_arm = set()

        for option in mips_opts:
            if mips_opts[option] > 30:
                self.above_avg_mips.add(option)
                
        for option in arm_opts:
            if arm_opts[option] > 85:
                self.above_avg_arm.add(option)
    
    def get_non_ds_options(self, kernel, arch, options, modules):
        
        structs_obj = Struct_Info(self.image, kernel, arch, modules)
        structs_obj.get_struct_info()
        # Get information about the upstream kernel modules
        vanilla_mod_dict, vanilla_mod_paths = structs_obj.find_upstream_modules()
        # Find which data structures are actually used by the kernel modules
        affected_structs = structs_obj.find_used_structs(vanilla_mod_dict, vanilla_mod_paths, modules)
        # print("Affected structs for image", image, "\n", affected_structs)

        structs_obj.get_all_opts_in_structs(affected_structs)
        print("All_opts in structs", structs_obj.all_opts_in_structs)
        
        # Now we got all the dangerous options affecting the structures used by the modules
        # Filter these options from Pandawan's popular option set
        print("Initial Pandawan options len", len(options))
        for option in options:
            if option in structs_obj.all_opts_in_structs:
                continue
            is_safe = structs_obj.check_if_in_struct(option)
            if is_safe:
                structs_obj.options_not_in_structs.add(option)
            else:
                print("Option", option, "is unsafe")
        
        print("Final Pandawan options len", len(structs_obj.options_not_in_structs))
        return list(structs_obj.options_not_in_structs)

    def get_safe_opts(self):
        
        # Get the info for the image
        info = cu.get_image_info(self.image, "all")
        if info['ksyms'] != []:
            print("Has KALL")
            return

        kernel_modules = info["modules"]
        #opts = self.above_avg_mips
        #opts.update(self.above_avg_arm)
        if info["arch"] == "mips":
            opts = self.above_avg_mips
        else:
            opts = self.above_avg_arm
        
        print("Opts", opts)
        kernel = f"linux-{info['kernel']}"
        options_not_in_structs = self.get_non_ds_options(kernel, info["arch"], opts, kernel_modules)
        
        info['pandawan'] = options_not_in_structs
        print("Options added to image", self.image, ":", len(options_not_in_structs))
        cu.save_image_info(self.image, info)
        
class Struct_Info(Kernel):
    def __init__(self, image, kernel, arch, modules):
        self.image = image
        self.modules = modules
        self.options_not_in_structs = set()
        super().__init__(kernel, arch)
        self.__get_config()

    def __get_config(self):
        kern_dir = f"{cu.kern_dir}{self.kernel}/"
        cwd = os.getcwd() 
        os.chdir(kern_dir)
        self.kconf = Kconfig("Kconfig", warn = False, warn_to_stderr = False)
        os.chdir(cwd)
 
    def find_upstream_modules(self):
        
        image_kernel_dir = f"{cu.result_dir_path}/{self.image}/{self.kernel}" 
        module_dir = f"{image_kernel_dir}/lib/modules/"
        
        mod_dir = os.listdir(module_dir)[0]                                                                                                               

        lib_dir = module_dir + mod_dir + "/"
        mod_dep = module_dir + mod_dir + "/modules.dep"
        
        #print(mod_dep , lib_dir)
        module_dict, module_paths = get_dictionary(mod_dep, lib_dir, image_kernel_dir)
        
        #print(module_paths)
        return module_dict, module_paths

    def get_all_opts_in_structs(self, affected_structs):
        all_opts_in_structs = set()
        for struct in affected_structs:
            # Struct name is not the dictionary with all the kernel structs. Bug?
            if struct not in self.struct_dict_conds:
                continue
            # There are no conditionals affecting the target struct's layout. Skip!
            if not self.struct_dict_conds[struct]['conds']:
                continue
            
            # Get the conditionals affecting the layout of the target struct
            the_options = get_struct_conditionals(self, struct)
            print("Struct:", struct)
            print("Affected opts", the_options)
            for opt in the_options:
                cleaned_options = self.get_cleaned_opts(opt)
                for clean_opt in cleaned_options:
                    all_opts_in_structs.add(clean_opt)

        self.all_opts_in_structs = all_opts_in_structs

    def get_cleaned_opts(self, option):
        # By clean we mean that even if we have an expression
        # we break it down to all the options that comprise it
        # e.g., A && B ----> [A, B]
        clean_options = set()
        or_opts = option.split("&&")
        and_opts = set()
        for opt in or_opts:
            opts = opt.split("||")
            for single_opt in opts:
                single_opt = single_opt.split()[0].replace("!","")
                and_opts.add(single_opt)
        
        for opt in and_opts:
            opt = opt.replace("!", "")
            clean_options.add(opt)

        return clean_options

    def find_used_structs(self, vmod_dict, vmod_paths, kernel_modules):
        upstream_mods = set()
        # Get the upstream counterparts of the firmware
        # image modules, if they exist
        for mod in kernel_modules:
            module = mod.split("/")[-1]
            module_bak = module.replace("-", "_")
            #if module in vmod_dict.keys():
                #upstream_mods.add(module)
            if module_bak in vmod_dict.keys():
                upstream_mods.add(module_bak)
        
        affected_structs = set()
        # Now its time to get which data structures are actually used by the upstream
        # kernel modules
        for mod in upstream_mods:
            # Get the path to the actual upstream module binary
            mod_path = vmod_paths[vmod_dict[mod]]
            print("Checking module", mod_path)
            # Now run pahole on the binary and get all the structs used by it
            # We will use subprocess for that
            pahole_cmd = f"pahole --structs -q -n {mod_path}"
            try:
                pahole_out = sb.check_output(pahole_cmd, shell = True).decode("utf-8")
            except Exception as e:
                print(e)
                raise
            
            for line in pahole_out.split("\n"):
                if line == "":
                    continue
                struct, _ = line.split()
                affected_structs.add(f"struct {struct}")
        
        return affected_structs

    def get_deps_and_selects(self, option):
        option_name = option.replace("CONFIG_", "") 
        if option_name in self.kconf.syms:
            try:
                sym = self.kconf.syms[option_name]
            except:
                return
        else:
            return
        # Dependencies can be logical expressions
        dependencies = expr_str(sym.direct_dep)
        # Selects as well
        # selects = sym.selects
        selects = []
        for select in sym.selects:
                selects.append(expr_str(select[0]))
            
        selects = " && ".join(selects)
            
        clean_options = self.get_cleaned_opts(dependencies)
        print(f"Option {sym.name} with clean deps {clean_options}")
        for opt in clean_options:
            self.deps_and_selects.add(opt)
            
        if selects == "": 
            return
        clean_options = self.get_cleaned_opts(selects)
        print(f"Option {sym.name} with clean selects {clean_options}")
        for opt in clean_options:
            self.deps_and_selects.add(opt)
            self.get_deps_and_selects(opt)

    def check_if_in_struct(self, option):
        self.deps_and_selects = set()
        self.get_deps_and_selects(option)
        # We want to see if dependencies and selects of the option do not modify
        # a data structure because it the option is enabled in FS then the deps
        # and selects are going to be enabled as well
        is_safe_opt = True
        for opt in self.deps_and_selects:
            if not opt.startswith("CONFIG_"):
                opt = "CONFIG_" + opt
            # This option is very problematic
            if opt in self.all_opts_in_structs:
                is_safe_opt = False
                return is_safe_opt
        
        return is_safe_opt