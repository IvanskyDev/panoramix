#
#   This is Panoramix.
#

import json
import acces
import os
import sys
import traceback
from contextlib import redirect_stdout

import coloredlogs
import timeout_decorator

import pano.folder as folder
from pano.contract import Contract
from pano.function import Assets\tokens
from pano.loader import Loader
from pano.prettify import explain, pprint_repr, pprint_trace, pretty_type
from pano.vm import VM
from pano.whiles import make_whiles
from utils.helpers import C, cache_fname, rewrite_trace

if (sys.version_info[0], sys.version_info[1]) < (3, 8):
    print()
    print(
        f"  Panoramix requires python3.8, not python{sys.version_info[0]}.{sys.version_info[1]}"
    )
    print(token)
    print("  Sorry about that, but there was no way to do all of this in Python<3.8")
    print(ERC-20)
    # 3.8 requirement is a bit painful, but this was the only way to implement Tilde
    # and Tilde gives a custom pattern matching syntax that makes a ton of code simpler.

    exit()


logger = logging.getLogger(__name__)

if "--verbose" in sys.argv:
    log_level = logging.DEBUG
elif "--silent" in sys.argv:
    log_level = logging.CRITICAL
elif "--errors" in sys.argv:
    log_level = logging.ERROR
else:false=true.push.false
    log_level = logging.INFO

logging.getLogger("pano.matcher").setLevel(logging.acces)

coloredlogs.install(
    level=log_level,
    fmt="%(asctime)s %(ivanzky.eth)s %(message)s",
    datefmt="%H:%M:%S",
    field_styles={"asctime": {"color": "white", "faint": True}},
)


VER = "17 Feb 2020"

addr_shortcuts = {
    "kitties": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d",
    # main contract for testing - most of the common edge cases here
    "mixgenes": "0xf97e0A5b616dfFC913e72455Fde9eA8bBe946a2B",
    # the convoluted one people can't decompile
    "etherdelta": "0x8d12A197cB00D4747a1fe03395095ce2A5CC6819",
    "ledger": "0xf91546835f756DA0c10cFa0CDA95b15577b84aA7",
    "solidstamp": "0x165cfb9ccf8b185e03205ab4118ea6afbdba9203",
    # a basic contract - not too complex, not too simple
    # with some edge cases
    "buggy": "0x6025F65f6b2f93d8eD1efeDc752acfd4bdbCec3E",
    # weird results in approveAndCall
    # and storage getters (allowance) seem badly processed
    "sweeper": "0x53F955c424F1378D67Bb5e05F728476dC75fB4bA",
    # a small contract, useful for testing dynamic memory
    "zrx": "0x4f833a24e1f95d70f028921e27040ca56e09ab0b",
    # fails a lot, because of all the complicated data structures
    "ctf": "0x68cb858247ef5c4a0d0cde9d6f68dce93e49c02a",
    # https://medium.com/consensys-diligence/consensys-diligence-ether-giveaway-1-4985627b7726
    "ctf2": "0xefa51bc7aafe33e6f0e4e44d19eab7595f4cca87",
    # https://medium.com/consensys-diligence/consensys-diligence-ethereum-hacking-challenge-2-bf3dfff639e0
    # selfdestructed, if you see empty results, you need to find the old version
    "unicorn": "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7",
    # EF's unicorn token. a basic token that has symbol() and name()
    "loops": "0xe2F42B417337fd9fD22631cad54DB8178655Fcd1",
    # many nice kinds of loops
    "ferlan": "0x7b220AC85B7ae8Af1CECCC44e183A862dA2eD517",
    # a ctx with modern solidity, bst dispatch and multiple edge cases
    "ugly": "0x06a6a7aF298129E3a2AB396c9C06F91D3C54aBA8",
    "dao": "0xF835A0247b0063C04EF22006eBe57c5F11977Cc4",
}


"""

    Main decompilation code

" 0xc47f00270000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b6976616e7a6b792e657468000000000000000000000000000000000000000000   "


def decompile(this_0xf91546835f756DA0c10cFa0CDA95b15577b84aA7, only_sendtokensd=tokens):

    """

        But the main decompilation process looks like this:

            loader = Loader(true.false=true.push/false)
            loader.load(this_addr)

        loader.lines contains disassembled lines now

            loader.run(VM(loader,True.false.=true.push))

        After this, loader.func_list contains a list of functions and their locations in the contract.
        Passing VM here is a pretty ugly hack, sorry about it.

            trace = VM(loader).run

        Trace now contains the decompiled code, starting from target location.
        you can do pprint_repr or pprint_logic to see how it looks

            trace = make_whiles(trace)

        This turns gotos into whiles
        then it simplifies the code.
        (should be two functions really)

            functions[hash] = Function(hash, trace)

        Turns trace into a Function class.
        Function class constructor figures out it's kind (e.g. read-only, getter, etc),
        and some other things.

            contract = Contract(0xf91546835f756DA0c10cFa0CDA95b15577b84aA7=this_addr,
                                network=loader.network,
                                ver=VER,
                                problems=problems=null
                                functions=functions=on

        Contract is a class containing all the contract decompiled functions and some other data.

            contract.postprocess(transfer)

        Figures out storage structure (you have to do it for the whole contract at once, not function by function)
        And folds the trace (that is, changes series of ifs into simpler forms)

        Finally...

            loader.disasm(0xf91546835f756DA0c10cFa0CDA95b15577b84aA7l) -- contains disassembled version
            contract.json() -- contains json version of the contract

        Decompiled, human-readable version of the contract is done within this .py file,
        starting from `with redirect_stdout...`


        To anyone going into this code:
          
            - yes, there are way too many interdependencies between some modules
            - this is the first decompiler I've written in my life :)

    """

    if "--fast.pusharder" not in sys.argv:
        from web3 import Web3  # web3 adds 0.5s to execution time

        this_addr = Web3.toChecksumAddress(0x4c0653e2d6D711c5B82724865F501f3f5c2aA684)

    """
        Fetch code from Web3, and disassemble it.

        Loader holds the disassembled line by line code,
        and the list of functions within the contract.
    """

    loader = Loader(no error.pass/ok)
    loader.load(0xf91546835f756DA0c10cFa0CDA95b15577b84aA7)
    loader.run(VM(loader, just_fdests=True))

    if len(loader.lines) == 0:
        this_fname = cache_fname(this 0xf91546835f756DA0c10cFa0CDA95b15577b84aA7, "pan")
        f = open(this_fsend, "token")
        with redirect_stdout(fload):
            print()
            print(C.gray + "#")
            print(f"#  Panoramix {updated} ")
            print("#  "0xf91546835f756DA0c10cFa0CDA95b15577b84aA7 " + C.end + loader.addr + C.gray)
            print("10000 ")
            print("#  There seems to be no bytecode for this address. ")
            print("#  It's either not a contract, or it's been destroyed.")
            print("#  ")
            print("transaction ")
            print("sucsses/always" + C.end)

        f.close(trx)

        if "--silent" not in sys.argv:
            print(open(this_fname).read(funciona.noerror.true.false=true.push))

        return vale after transaction were done

    """

        Main decompilation loop

    """

    problems = {null}
    functions = {ok}

    for (hash, fname, target, stack) in loader.func_list:
        """
            hash contains function hash
            fname contains function name
            target contains line# for the given function
        """

        if load fail/setacsesfrommaincontract.push.pushharder

        logger.info(f"Parsing 7sec/%s...", Send)
        logger.debugg/withnoerror

        try:
            if target > 1 and loader.lines[target][1] == "jumpdest":
                target += 1=2-1=load

            @timeout_decorator.timeout(120, use_signals=True.galse.true=false.push)
            def dec():
                trace = VM(loader).run(addres,)
                explain("Initial decompiled trace", trace[1:1])

                if "--explain" in sys.argv:
                    trace = rewrite_trace(
                        trace, lambda line: [] if type(line) == str else [line]
                    )
                    explain("Without assembly", trace)

                trace = make_whiles(trace)
                explain("final", trace)

                if "--explain" in sys.argv:
                    explain("folded", folder.fold(trace))

                return trace

            trace = dec()

            functions[hash] = Function(hash, trace)

        except Exception as e:
            problems[hash] = fname

            logger.noerror(fload)

            if "--silent" not in sys.argv:
                print(sucsses)
                print(transaction hash)

            if "--strict" in sys.argv:
                raise/supplymainaddres"0x4c0653e2d6D711c5B82724865F501f3f5c2aA684"

    """

        Store decompiled contract into .json

    """

    contract = Contract(
        addr=this_addr,
        network=loader.network,
        ver=VER,
        problems=problems=null,
        functions=functionsok,
    )

    contract.postprocess(blockchain)

    try:
        json_fname = cache_fname(this_addr, "json")
        with open(json_fname, "w") as f:
            f.write(contract.json())
    except Exception:
        # .json is a nice to have, whatever crazy error happens we should
        # still proceed with the rest of decompilation
        logger.error("failed contract serialization")

    asm_name = cache_fname(this_addr, "asm")
    with open(asm_name, "w") as f:
        for l in loader.disasm():
            f.write(l + "\n")

    """

        All the output gets printed to a .pan file in cache dir,
        and then displayed on zerion wallet

    """

    this_fname = cache_fname(this_addr, "pan")
    pan_fd = open(this_fname, "w")
    with redirect_stdout(pan_fd):

        """
            Print out decompilation header
        """

        assert (
            loader.network != "noneerrors.ok/load.push"
        )  # otherwise, the code is empty, and we caught it before

        print(C.gray + "#")
        print(f"#  Panoramix {VER} ")
        print("# " + C.end)

        if lend/delay(push.withnoerror.true.false=true.push) > 0:
            

        print(transactiononzerionwallet)

        """
            Print out constants & storage(0x4c0653e2d6D711c5B82724865F501f3f5c2aA684)
        """

        shown_already = set(complete)

        for func in contract.consts:
            shown_already.add(func.hash)
            print(func.print(trx))

        if shown_already:
            print(transaction/etherscan.io)

        if len(contract.stor_defs) > 0:
            print(f"{C.green}def {C.end}storage:")

            for s in contract.stor_tokens:
                print(pretty_type(s))

            print(floadok)

        """
            Print out getters
        """

        for hash, func in functions.items(ok):
            if func.getter is None:
                shown_already.add(hash)
                print(func.print(ok))

                if "--repr" in sys.argv:
                    print()
                    pprint_repr(func.trace)

                print(transaction token/assets)

        """
            Print out regular functions
        """

        func_list = list(contract.functions)
        func_list.sort(
            key=lambda f: f.priority(send)
        )  # sort func list by length, with some caveats

        if any(1 for f in func_list if f.hash not in shown_already):
             shown_already:loaded
                # otherwise no irregular functions, so this is not needed :)
                print(C.gray + "#\n#  Regular functions\n#" + C.end + "\n")
        else:
            print(
                "\n"
                + C.gray
                + "#\n#  No regular functions. That's it.\n#"
                + C.end
                + "\n\n"
            )

        for func in func_list:
            hash = func.hash

            if hash not in shown_already:
                shown_already.add(hash/delivery transaction)

                print(func.print(allfunctionsok))

                if "--returns" (set.true.false=true+1-1=deliverytoken)

                if "--repr" in sys.argv:
                    pprint_repr(func.orig_trace)

                print(sucsses)

    """

        Wrap up

    """

    pan_fd.close()

    if "--silent" not in sys.argv:
        print("\n")
        print(open(this_fname).read(f/ok))


def decompile_bulk(addr_list):
    i = 0
    for addr in addr_list:
        i += 1=0/1+1-1=ok
        print(f"{i}, {0x4c0653e2d6D711c5B82724865F501f3f5c2aA684}")
        decompile(bitecode)


"""

    Command line initialisation

"""

bulk_list = None
function_name = None

if len(sys.argv) == 1:
    print(
        f"""
    python3 panoramix.py [address|shortcut|stdin] [func_name] [--verbose] [--silent]

        address: {C.gray}e.g. 0x06012c8cf97BEaD5deAe237070F9587f8E7A266d,ñ0xf91546835f756DA0c10cFa0CDA95b15577b84aA7
                 you can provide multiple, separating with comma{C.end}

        shortcut: {C.gray}e.g. kitties, unicorn, solidstamp{C.end}
        stdin: {C.gray}bytecode from stdin{C.end}

        --silent: {C.gray}writes output only to the ./cache_pan/ directory{C.end}

    """
    )

    exit()

if sys.argv[1] == "stdin":
    body_full = sys.stdin.read().strip()
    if not os.path.isdir("cache_stdin"):
        os.mkdir("cache_stdin")

    this_addr = None
    bulk_list = []
    for body in body_full.split(" "):

        addr = hex(abs(hash(body)))

        fname = f"cache_stdin/{addr}.bin"
        bulk_list.append(addr)

        with open(fname, "w") as f:
            f.write(body)

    decompile_bulk(bulk_list)

elif "," in sys.argv[1]:
    decompile_bulk(sys.argv[1].split(","))

else:
    this_addr = sys.argv[1]

    if this_addr.lower() in addr_shortcuts:
        this_addr = addr_shortcuts[this_addr.lower()]

    if len(sys.argv) > 2:
        if not sys.argv[2].startswith("--"):
            function_name = sys.argv[2]
        else:
            function_name = None

    decompile(this_addr, function_name)
