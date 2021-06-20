#!/usr/bin/env python3

import shutil
import glob
import argparse
import sys
import os
import os.path
import time
import subprocess
import threading

from concurrent.futures import ThreadPoolExecutor

from ilmklib import Graph, makedeps, WorkQueue, TimestampDict

def ts_directory(dirname):
    if os.path.exists(dirname):
        if not os.path.isdir(dirname):
            raise RuntimeException(f"{dirname} exists and is not a directory")
        else:
            return 0

    else:
        return -1

def ts_file(fname):
    if os.path.exists(fname):
        if not os.path.isfile(fname):
            raise RuntimeException(f"{fname} exists and is not a regular file")
        else:
            return os.path.getmtime(fname)

    return -1

def simple_compile(compiler, src, obj, codegen, includedirs, libdirs, libs):

    cmd = [compiler, "-c", "-o", obj, src]

    cmd.append(" ".join(codegen))
    cmd.extend([ f"-I{x}" for x in includedirs])
    cmd.extend([ f"-L{x}" for x in libdirs])
    cmd.extend([ f"-l{x}" for x in libs])


    print(cmd)
    subprocess.check_output(cmd)


def do_task(g, compiler, finale, item):

    # If the item was put into the graph with the directory timestamp function,
    # it's a directory.
    item_type = g[item]
    if item_type == "directory":
        print(f"Making directory {item}")
        os.makedirs(item)
    elif item_type == "object_file":
        # If the item is an object file, find the .c file in its predecessors and compile it
        # Find the c file
        cf = filter(lambda x: x.endswith(".c"), g.get_direct_predecessors(item))
        x = next(cf)

        simple_compile(compiler, x, item, ["-Ofast"], ["inc"], [], [])
    elif item_type == "main_output":
        # Otherwise its the final output. Find all the object files that go
        # into it and compile it.
        of = filter(lambda x: x.endswith(".o"), g.get_direct_predecessors(item))
        final_cmd = ["ar", "rcs"] + [finale] + list(of)
        print(final_cmd)
        subprocess.check_output(final_cmd)
    else:
        print(f"Unexpected item type for {item}")


def tw(w, g, tsd, finale):

    cc = tsd["cc"]
    while True:

        item = w.get_item(True)
        if not item:
            break

        try:
            do_task(g, cc, finale, item)
        except Exception as e:
            print(e)
            w.mark_error()
            return

        w.mark_done(item)

def do_main():

    # Do argument parsing
    parse = argparse.ArgumentParser(add_help=False)
    parse.add_argument('-v', '--verbose', action='count', default=0)
    parse.add_argument('-m', '--multitask', action='store_true')
    parse.add_argument('-j', '--jobs', type=int, default=1)
    parse.add_argument('-t', '--targets', nargs='*')
    #parse.add_argument('targets', nargs='*')
    args = parse.parse_args(sys.argv[1:])
    if args.multitask:
        ncpus = os.cpu_count()
    else:
        ncpus = args.jobs

    tsd = TimestampDict()
    tsd.loadkeydir(".env_vars")

    # Default cc to gcc
    if not "cc" in tsd:
        tsd["cc"] = "gcc"

    targets = args.targets if args.targets else []
    for target in targets:
        if target == "clean":
            try:
                shutil.rmtree("out")
            except:
                pass
            return
    # Create the graph, add the output directory(ies)
    g = Graph()
    g.add_vertex("out", "directory")

    # Add the final binary name
    finale = os.path.join("out", "libspooky.a")
    g.add_vertex(finale, "main_output")

    g.add_vertex(tsd.name("cc"), "tsd_entry")

    g.add_edge(finale, tsd.name("cc"))

    # Find all the headers and c source files
    cfiles = glob.glob("src/**.c")
    hfiles = glob.glob("inc/**.h")

    for f in hfiles:
        # Add all the headers to the graph
        g.add_vertex(f, "file")

    mkdeps = []
    # Run makedeps on each of the source files with the inc dir
    with ThreadPoolExecutor() as executor:
        mkdeps = executor.map(lambda x:(x, *makedeps(x, "inc", False, tsd["cc"])), cfiles)

    test_binaries = []

    for f, o, deps in mkdeps:
        # Add all the c source files to the graph
        g.add_vertex(f, "file")
        # Run makedeps on each of the source files with the inc dir
        #o, deps = cc.makedeps(f, "inc")

        # Add the object file to the graph
        ofile = os.path.join("out", o)
        g.add_vertex(ofile, "object_file")

        # Add edges from `out/` to the object file
        g.add_edge(ofile, "out")
        # Headers + c file to object file
        g.add_edges(ofile, deps)

        g.add_edge(ofile, tsd.name("cc"))

        # object file to final output
        g.add_edge(finale, ofile)

    ts_tsd_entry = lambda x : tsd.time(x)
    func_dict = {
        "file" : ts_file,
        "directory" : ts_directory,
        "main_output" : ts_file,
        "object_file" : ts_file,
        "tsd_entry" :  ts_tsd_entry,
    }

    # Create a work queue with the end goal of the finale file
    w = WorkQueue(g, finale, func_dict)

    if "print" in targets:
        for item in w.get_updated():
            print(item)
        sys.exit(0)

    threads = []
    nthreads = ncpus

    # Create and start some threads
    for i in range(nthreads):
        t = threading.Thread(target=tw, args=(w, g, tsd, finale))
        threads.append(t)
        t.start()

    # Wait for all the threads to complete
    for t in threads:
        t.join()

    # If there was some error, exit with a nonzero code
    if w.error:
        sys.exit(1)


if __name__ == "__main__":
    do_main()
