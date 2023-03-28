from itertools import chain
import angr
import os, json, logging
import claripy

log = logging.getLogger(__name__)
sim_options = angr.sim_options


def flatten(list): # helper to flatten a list
    return chain.from_iterable(list)

def disassemble(func:str, proj:angr.Project):
    cfg = proj.analyses.CFGEmulated()
    if type(func) == int:
        function = cfg.functions.get_by_addr(func)
    else:
        function = cfg.functions.get(func)
    print(proj.analyses.Disassembly(function).render())
    return cfg

def hash_state(state: angr.sim_state.SimState):
    state_hash = 0
    for index, frame in enumerate(state.callstack):
        state_hash ^= frame.func_addr << index
    return state_hash

def print_cs(state: angr.sim_state.SimState, proj: angr.Project):
    print(f"current addr: {hex(state.addr)}, name: {proj.loader.find_symbol(state.addr)}")
    print()
    print(f"constraints: {state.solver.constraints}")
    print()

    for i, cs in enumerate(state.callstack):
        callsite = cs.call_site_addr
        func = cs.func_addr
        callsite_name = None
        func_name = None

        if proj.loader.find_symbol(callsite) != None and proj.loader.find_symbol(func) != None:
            func_name = proj.loader.find_symbol(func).name
            callsite_name = proj.loader.find_symbol(callsite).name
        else:
            pass

        print(f"frame: {i}, call_site: {hex(callsite)} in {(callsite_name)} called: {hex(func)} in {(func_name)}")
    print()
    print()

# Copied from ARCUS: https://github.com/carter-yagemann/ARCUS

def parse_entry_state_json(
    project, trace_dir, snapshot_dir, prep_explore=False, override_max_argv=None
):
    """Creates an initial state for the trace.

    Keyword Arguments:
    project -- The Angr Project this state is being created for.
    trace_dir -- The trace directory.
    snapshot_dir -- The snapshot directory. Might be the same as trace_dir, or a subdirectory.
    prep_explore -- Tweak entry state in ways that are more likely to expose bugs.
    Only relevant if explorer plugins are going to be used.

    Returns:
    A tuple (state, argv/env dict) or (None, None) if there was an error.
    """
    state_path = os.path.join(trace_dir, "state.json")
    regs_path = os.path.join(snapshot_dir, "regs.json")
    files_path = os.path.join(trace_dir, "files.json")
    misc_path = os.path.join(snapshot_dir, "misc.json")

    is_snapshot = not (trace_dir == snapshot_dir)

    # get argv/env state, register states, memory dumps, file dumps and
    # misc data from trace directory
    log.info("Loading state from: %s", state_path)
    with open(state_path, "r") as json_file:
        state_json = json.load(json_file)
    log.info("Loading regs from: %s", regs_path)
    with open(regs_path, "r") as ifile:
        regs = json.load(ifile)
    if os.path.exists(files_path):
        log.info("Loading files from: %s", files_path)
        with open(files_path, "r") as ifile:
            fs_files = json.load(ifile)
    else:
        log.info("No filesystem info provided")
        fs_files = None
    log.info("Loading misc from: %s", misc_path)
    with open(misc_path, "r") as ifile:
        misc = json.load(ifile)

    # parse argv and env
    argv = list()
    env = dict()
    if override_max_argv is None:
        argv_max = 0x2000 * 8  # bits
    else:
        argv_max = override_max_argv * 8

    for keyword in state_json:
        if keyword == "argv":
            for arg in state_json["argv"]:
                if prep_explore and arg["type"] == "BVS":
                    argv.append(claripy.BVS("argv", argv_max))
                elif arg["type"] == "BVS":
                    argv.append(claripy.BVS("argv", arg["value"]))
                elif arg["type"] == "BVV":
                    argv.append(claripy.BVV(arg["value"], arg["size"]))
                elif arg["type"] == "str":
                    argv.append(arg["value"])
                else:
                    log.warning("Invalid argv type: %s" % arg["type"])
        elif keyword == "env":
            for env_item in state_json["env"]:
                # create bitvector for key
                if prep_explore and env_item["key_type"] == "BVS":
                    env_key = claripy.BVS(env_item["key_val"], argv_max)
                elif env_item["key_type"] == "BVS":
                    env_key = claripy.BVS(env_item["key_val"], env_item["key_size"])
                elif env_item["key_type"] == "BVV":
                    env_key = claripy.BVV(
                        env_item["key_val"], size=env_item["key_size"]
                    )
                elif env_item["key_type"] == "str":
                    env_key = env_item["key_val"]
                else:
                    log.warning("Invalid env key type: %s" % env_item["key_type"])
                    continue
                # bitvector for value
                if prep_explore and env_item["val_type"] == "BVS":
                    env_val = claripy.BVS(env_item["val_val"], argv_max)
                elif env_item["val_type"] == "BVS":
                    env_val = claripy.BVS(env_item["val_val"], env_item["val_size"])
                elif env_item["val_type"] == "BVV":
                    env_val = claripy.BVV(
                        env_item["val_val"], size=env_item["val_size"]
                    )
                elif env_item["val_type"] == "str":
                    env_val = env_item["val_val"]
                else:
                    log.warning("Invalid env value type: %s" % env_item["val_type"])
                    continue
                # update the env dict
                env[env_key] = env_val
        else:
            log.warn("Unsupported keyword: %s", keyword)

    # add options to our initial state
    extra_opts = {
        sim_options.SIMPLIFY_CONSTRAINTS,
        sim_options.SIMPLIFY_EXPRS,
        sim_options.SIMPLIFY_MEMORY_WRITES,
        sim_options.SIMPLIFY_REGISTER_WRITES,
    }
    extra_opts |= {sim_options.ALL_FILES_EXIST}
    extra_opts |= {sim_options.LAZY_SOLVES}

    state = project.factory.entry_state(args=argv, env=env, add_options=extra_opts)
    # register deepcopy version of globals plugin for plugins that do not want data shared between states
    #state.register_plugin("deep", SimStateDeepGlobals())

    # restore registers
    sp_name = project.arch.register_names[project.arch.sp_offset]
    bp_name = project.arch.register_names[project.arch.bp_offset]
    for reg in regs:
        if not is_snapshot and reg in [sp_name, bp_name]:
            # we made a new stack so symbolic variables could be added,
            # don't point the state back at the original (it doesn't exist anymore)
            continue
        if not reg in project.arch.registers:
            continue
        try:
            setattr(state.regs, reg, regs[reg])
        except:
            log.warn("State does not have register %s" % reg)

    # we're about to restore memory, but don't want to overwrite relocations
    # because CLE already resolved them to add things like hooks for simulation procedures
    orig_relocs = dict()
    for obj in project.loader.all_objects:
        for reloc in obj.relocs:
            if reloc.symbol is None or reloc.resolvedby is None:
                continue

            gotaddr = reloc.rebased_addr
            gotvalue = project.loader.memory.unpack_word(gotaddr)
            orig_relocs[gotaddr] = gotvalue

    # restore memory
    mem_dir = os.path.join(snapshot_dir, "mem/")
    for item in os.listdir(mem_dir):
        fullfp = os.path.join(mem_dir, item)
        base_va = int(item.split("-", 1)[0], 16)
        end_va = base_va + os.path.getsize(fullfp)

        name = item.split("-", 1)[1][:-4]
        if name == "0":
            name = "null"

        if not is_snapshot and name in ["[stack]"]:
            # we created a new stack for the analysis, so don't load in the original
            # heap is fine though because our snapshot includes the brk
            continue

        with open(fullfp, "rb") as ifile:
            log.debug("Restoring %s at %#x" % (name, base_va))
            state.memory.store(base_va, ifile.read())

    # restore CLE's relocations
    for gotaddr in orig_relocs:
        gotvalue = orig_relocs[gotaddr]
        state.memory.store(addr=gotaddr, data=gotvalue,
                size=state.arch.bits // 8, endness=state.arch.memory_endness)

    # create simulated filesystem
    if not fs_files is None:
        if len(fs_files["files"]) > 0 and "BVS" in [
            arg["type"] for arg in state_json["argv"]
        ]:
            log.warning(
                "The traced program appears to have received files via argv, but argv"
                " has been symbolized, so angr will not know their sizes. This can"
                " cause analysis to become VERY slow."
            )

        state.fs.cwd = fs_files["cwd"].encode("utf8")
        for fp in fs_files["files"]:
            data_fp = os.path.join(trace_dir, fs_files["files"][fp]["data"])
            data_sym = fs_files["files"][fp]["symbolic"]
            if not os.path.isfile(data_fp):
                log.warn("Could not find %s" % data_fp)
                continue

            with open(data_fp, "rb") as ifile:
                data = ifile.read()
                data_len = len(data)
                if data_sym:
                    data = None

            simfile = angr.SimFile(
                fp, content=data, size=data_len, has_end=True, concrete=True
            )
            simfile.set_state(state)
            log.debug("Inserting %s" % fp)
            state.fs.insert(fp, simfile)

    # restore brk, otherwise heap layout won't match what was traced
    state.posix.brk = misc["brk"]

    return (state, {"argv": argv, "env": env})