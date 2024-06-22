#! /usr/bin/env python3

import os
import pickle
from multiprocessing import Pool
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
import paths as pt

tools = ["pandawan", "firmsolo", "firmae", "firmadyne"]

def get_data(infile):
    with open(infile,"rb") as f:
        data = pickle.load(f)

    return data

def get_bbs_from_tool(data):
    tool, image = data[0], data[1]
    mod_bbs = set()

    print(f"Getting KO coverage for tool {tool} and image {image}")
    try:
        coverage_fl = f"{pt.output_dir}/{tool}_results/scratch/{image}/exec_context.pkl"
        try:
            cov = get_data(coverage_fl)
        except:
            print("No coverage for image", image, "and tool", tool)

        for trace in cov:
            mod_bbs.update(cov[trace])
    except:
        return[tool, image, set()]
    
    return [tool, image, mod_bbs]

def collect_kmod_coverage(image):
    
    data = []
    for tool in tools:
        data.append([tool, image])

    p = Pool(4)
    res = p.map(get_bbs_from_tool, data)
    
    bbs_per_tool = {}
    
    for result in res:
        tool = result[0]
        bbs = result[2]

        if tool not in bbs_per_tool:
            bbs_per_tool[tool] = 0

        bbs_per_tool[tool] += len(bbs)
    
    return bbs_per_tool