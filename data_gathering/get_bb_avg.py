#! /usr/bin/env python3


import os
from multiprocessing import Pool
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
import paths as pt

tools = ["pandawan", "firmsolo", "firmae", "firmadyne"]

def get_data(infile):
    with open(infile,"r") as f:
        lines = f.readlines()

    data = list(map(lambda x:x.strip("\n"), lines))

    return data

def get_bbs_from_tool(data):
    tool, image = data[0], data[1]
    all_coverage = {}

    print(f"Getting BB coverage for system {tool} and image {image}")
    coverage_fl = f"{pt.output_dir}/{tool}_results/scratch/{image}/coverage.csv"
    try:
        cov = get_data(coverage_fl)
    except:
        print(f"There is no coverage for image {image} and system {tool}. Did PANDA collect coverage or did the experiments not run?")
        return [tool, {}]
    
    for indx, proc in enumerate(cov[4:]):
        if "\t" in proc:
            try:
                addr = proc.split(" ")[2]
                offst = proc.split(" ")[0].strip("\t")
                origin = proc.split(" ")[-1]
                if origin not in all_coverage:
                    all_coverage[origin] = set()
                all_coverage[origin].add(offst)
                continue
            except:
                continue
    return [tool, all_coverage]

def get_user_bbs(image):
    data = []
    for tool in tools:
        data.append([tool, image])
    
    p = Pool(4)
    res = p.map(get_bbs_from_tool, data)
    
    coverage = {}
    bbs = {}
    unique_bbs = {}
    procs = {}

    for result in res:
        tool = result[0]
        coverage = result[1]
        if tool not in bbs:
            bbs[tool] = 0
            unique_bbs[tool] = 0
            procs[tool] = 0

        for proc in coverage:
            unique_bbs[tool] += len(coverage[proc])
            procs[tool] += 1
    
    return unique_bbs, procs
