#!/usr/bin/env python3
import argparse
from cimgparse import CIMGFile, Directive4DrawSprite, parse_cimg


def patch_cimg(cimg: CIMGFile):
    draws = 0
    char_w, char_h, line_cap = 8, 8, 16
    for directive in cimg.directives:
        if isinstance(directive, Directive4DrawSprite):
            directive.x = char_w * draws % (char_w * line_cap)
            directive.y = (draws // line_cap) * char_h
            draws += 1
    cimg.header.width = char_w * line_cap
    cimg.header.height = (draws // line_cap + 1) * char_h
    return cimg


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse cIMG and render terminal output."
    )
    parser.add_argument(
        "path", nargs="?", default="flag.cimg", help="path to cIMG file"
    )
    args = parser.parse_args()
    cimg = parse_cimg(args.path)
    cimg = patch_cimg(cimg)
    cimg.display()


if __name__ == "__main__":
    main()
