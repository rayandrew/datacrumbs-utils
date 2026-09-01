"""Generate the GOTCHA wrap list for the classified API surface.

Generated from the headers with libclang, as dftracer does for HDF5 and MPI: a generic wrapper
cannot forward arguments without the real prototype, and 381 hand-written wrappers do not scale.
Emits one X-macro entry per symbol; the wrapper body and the binding table are hand-written once
against that list, so adding a library is a regeneration.

Variadic functions are skipped and reported: forwarding a va_list needs a v-form of the callee
(vprintf to printf), which most of this surface does not have.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Imported lazily, so the op tables still build wherever the wrap list is skipped.
cix = None


_INT_KINDS = frozenset()


def _load_clang(libclang):
    global cix, _INT_KINDS
    import clang.cindex

    cix = clang.cindex
    # Once per process: libclang refuses a second call.
    cix.Config.set_library_file(libclang)
    _INT_KINDS = frozenset(
        getattr(cix.TypeKind, k)
        for k in (
            "BOOL", "CHAR_U", "UCHAR", "USHORT", "UINT", "ULONG", "ULONGLONG",
            "CHAR_S", "SCHAR", "SHORT", "INT", "LONG", "LONGLONG", "ENUM",
        )
    )

# Wrap everything classified and trim with --skip-classes: re-running a sweep costs far more than
# reading a large trace. `other` is the absence of a classification, not a class.
SKIP_CLASSES = ("other",)

# Symbols better wrapped by hand: the ibverbs hot path dispatches through qp->context->ops, so
# rdma_hwts.cpp patches it instead of wrapping it here.
OVERRIDE = set()

# A flag word arrives as a plain `int access`, so the type names no enum. Only the association is
# written here; the decoders come from the enums themselves.
FLAG_ARGS = {
    ("ibv_reg_mr", "access"): "ibv_access_flags",
    ("ibv_reg_mr_iova", "access"): "ibv_access_flags",
    ("ibv_reg_mr_iova2", "access"): "ibv_access_flags",
    ("ibv_rereg_mr", "access"): "ibv_access_flags",
    ("ibv_alloc_mw", "type"): "ibv_mw_type",
    ("ibv_modify_qp", "attr_mask"): "ibv_qp_attr_mask",
    ("ibv_modify_srq", "srq_attr_mask"): "ibv_srq_attr_mask",
    ("ibv_query_qp", "attr_mask"): "ibv_qp_attr_mask",
}


# A DevX call carries its opcode in the first two bytes of `in`, big endian, not in a parameter.
# Without this a trace says a command was issued and never which one.
CMD_ARGS = {
    ("mlx5dv_devx_general_cmd", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_obj_create", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_obj_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_obj_query", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_qp_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_qp_query", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_cq_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_cq_query", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_srq_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_srq_query", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_wq_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_wq_query", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_ind_tbl_modify", "in"): ("inlen", "MLX5_CMD_OP"),
    ("mlx5dv_devx_ind_tbl_query", "in"): ("inlen", "MLX5_CMD_OP"),
}


# An op carried in an attribute struct rather than as a parameter, where neither the parameter type
# nor the field type names the enum. Only the association is written here; the offset and width come
# from the headers, so a struct that gains a member does not shift what gets read.
#
# (function, parameter) -> [(field, decoder)]
FIELD_ARGS = {
    ("flexio_cq_create", "fattr"): [("element_type", "FLEXIO_CQ_ELEMENT_TYPE")],
}


def field_layout(ctype, field):
    """(offset_bytes, width_bytes) of @p field in the struct @p ctype points to, or None.

    Read from the header, not tabulated: a written-down offset reads the wrong bytes as soon as
    someone adds a member above it.
    """
    canon = ctype.get_canonical()
    if canon.kind == cix.TypeKind.POINTER:
        canon = canon.get_pointee().get_canonical()
    if canon.kind != cix.TypeKind.RECORD:
        return None
    decl = canon.get_declaration()
    for c in decl.get_children():
        if c.kind == cix.CursorKind.FIELD_DECL and c.spelling == field:
            bit = canon.get_offset(field)
            if bit < 0 or bit % 8:
                return None
            size = c.type.get_size()
            if size not in (1, 2, 4, 8):
                return None
            return bit // 8, size
    return None


def declare(type_spelling, name):
    """Declare @p name with @p type_spelling, as C syntax requires rather than by concatenation.

    A pointer to an array or a function puts the name inside the parentheses: `char (*name)[64]`.
    An array parameter decays to a pointer, since `T[] name` does not parse.
    """
    t = type_spelling.strip()
    if "(*)" in t:
        return t.replace("(*)", f"(*{name})", 1)
    if t.endswith("]"):
        return f"{t[: t.rindex('[')].strip()} * {name}"
    return f"{t} {name}"


def built_against(headers, includes):
    """Versions of the libraries these headers describe, keyed by library.

    A trace decodes with names read from these headers, so it is only interpretable against a
    matching library. DOCA carries its version in a header; rdma-core needs pkg-config.
    """
    found = {}
    for d in list(includes) + [str(Path(h).parent) for h in headers]:
        v = Path(d) / "doca_version.h"
        if v.exists():
            m = re.search(r'#define\s+DOCA_VERSION_STRING\s+"([^"]+)"', v.read_text())
            if m:
                found["doca"] = m.group(1)
                break
    for pkg, key in (("libibverbs", "ibverbs"), ("libmlx5", "mlx5")):
        try:
            r = subprocess.run(
                ["pkg-config", "--modversion", pkg], capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and r.stdout.strip():
                found[key] = r.stdout.strip()
        except Exception:
            pass
    return found


_CONST_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*,?\s*(?:/\*.*)?$", re.M)


def constants_by_prefix(path, prefix):
    """(name, value) for every `PREFIX_* = <int>` in @p path, read as text.

    The DevX command opcodes live in the kernel's mlx5_ifc.h, which no userspace build can parse:
    libclang stops at the first u8 and takes all 192 opcodes with it. A list of names and numbers
    needs no parser.
    """
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    out = []
    for name, val in _CONST_RE.findall(text):
        if name.startswith(prefix):
            out.append((name, int(val, 0)))
    return out


def common_prefix(names):
    """The identifier prefix these constants share, trimmed at an underscore. Empty if too short.

    Names an anonymous enum by its members: MLX5_CMD_OP_QUERY_HCA_CAP and its 191 siblings give
    MLX5_CMD_OP. At least three members, so two unrelated constants give no meaningless key.
    """
    if len(names) < 3:
        return ""
    head = names[0]
    for n in names[1:]:
        while not n.startswith(head):
            head = head[:-1]
            if not head:
                return ""
    head = head.rstrip("_")
    return head if head.count("_") >= 1 else ""


def enum_key(ctype):
    return re.sub(r"[^A-Za-z0-9_]", "_", ctype.get_canonical().spelling)


def enum_constants(ctype):
    """(name, value) for an enum-typed argument, or None. Empty for an opaque forward declaration."""
    canon = ctype.get_canonical()
    if canon.kind != cix.TypeKind.ENUM:
        return None
    decl = canon.get_declaration()
    return [
        (c.spelling, c.enum_value)
        for c in decl.get_children()
        if c.kind == cix.CursorKind.ENUM_CONSTANT_DECL
    ]


def arg_kind(ctype):
    """How much of an argument is worth recording.

    A pointer to an opaque struct keeps its address: the same qp on a post and on its completion is
    what joins them. Decided from the canonical type, since a typedef'd callback is spelled like a
    plain identifier and would otherwise be cast to an integer.
    """
    canon = ctype.get_canonical()
    if canon.kind in _INT_KINDS:
        return "int"
    if canon.kind == cix.TypeKind.POINTER:
        pointee = canon.get_pointee().get_canonical()
        if pointee.kind == cix.TypeKind.FUNCTIONPROTO:
            return "skip"
        # A string has unbounded length and the caller's lifetime.
        if pointee.kind in (cix.TypeKind.CHAR_S, cix.TypeKind.CHAR_U, cix.TypeKind.SCHAR,
                            cix.TypeKind.UCHAR):
            return "skip"
        return "ptr"
    return "skip"


def prototypes(header, includes, all_enums, enum_src=None):
    """Prototypes declared in @p header, keyed by symbol. Empty if it does not parse.

    A header needing a different compiler is skipped rather than fatal: the DPA device headers use
    __dpa_global__, which clang rejects, and declare code the host cannot call anyway.
    """
    tu = cix.Index.create().parse(header, args=[f"-I{i}" for i in includes])
    bad = [d for d in tu.diagnostics if d.severity >= cix.Diagnostic.Error]
    # A header that fails to parse still yields the enums libclang reached, and mlx5_ifc.h is where
    # the 192 DevX command opcodes live. Prototypes are refused, op tables are not.
    if bad:
        print(f"// prototypes skipped, enums kept, {Path(header).name}: {bad[0].spelling}",
              file=sys.stderr)
    out = {}
    for c in tu.cursor.get_children():
        if c.kind == cix.CursorKind.ENUM_DECL:
            consts = [
                (k.spelling, k.enum_value)
                for k in c.get_children()
                if k.kind == cix.CursorKind.ENUM_CONSTANT_DECL
            ]
            # The op tables that matter are anonymous `enum {`, so a name-only key would miss the
            # ones worth decoding; key those by the shared prefix. An anonymous enum is spelled
            # "enum (unnamed at file:line)", not empty.
            named = c.spelling and "(unnamed" not in c.spelling
            key = c.spelling if named else common_prefix([n for n, _ in consts])
            if key and consts:
                all_enums.setdefault(key, consts)
                if enum_src is not None:
                    enum_src.setdefault(key, header)
        if c.kind != cix.CursorKind.FUNCTION_DECL or bad:
            continue
        args = list(c.get_arguments())
        # Unnamed parameters are legal in a declaration; a wrapper still has to forward them.
        named = [(declare(a.type.spelling, a.spelling or f"a{i}"), a.spelling or f"a{i}", a.type)
                 for i, a in enumerate(args)]
        # An old-style declaration is FUNCTIONNOPROTO, and asking it whether it is variadic asserts
        # rather than answering. Treated as variadic, so it is reported and skipped.
        variadic = (
            c.type.is_function_variadic()
            if c.type.kind == cix.TypeKind.FUNCTIONPROTO
            else True
        )
        out[c.spelling] = (c.result_type.spelling, named, variadic)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("headers", nargs="*")
    ap.add_argument("--libclang")
    ap.add_argument("--include", action="append", default=["/usr/include"])
    ap.add_argument("--inventory", default=str(Path(__file__).parent / "api-inventory.tsv"))
    ap.add_argument("--output", help="write here instead of stdout")
    ap.add_argument(
        "--split-dir",
        help="also write one wrap list per library under DIR/<lib>/api.h, each defining "
        "DC_WRAPPED_FUNCS for its own library only",
    )
    ap.add_argument(
        "--skip-classes",
        default=",".join(SKIP_CLASSES),
        help="comma-separated inventory classes to leave unwrapped",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="emit a program that checks each decoder against the constants the compiler resolves "
        "from the same headers, so the extraction is validated by a second parser",
    )
    ap.add_argument(
        "--only-decoders",
        action="store_true",
        help="emit just the op tables, for a shim that decodes values it read itself",
    )
    ap.add_argument(
        "--decode-constants",
        action="append",
        default=[],
        help="PREFIX=path: emit a decoder for every PREFIX_* constant in that header, read as text "
        "rather than parsed. For op tables in headers no userspace build can compile.",
    )
    ap.add_argument(
        "--tramp-out",
        help="write a DC_TRAMP_FUNCS list here for the variadic symbols no wrapper can forward",
    )
    ap.add_argument(
        "--selftest-device",
        action="store_true",
        help="emit a translation unit asserting the value of every constant whose header only "
        "compiles for the device, to be checked with the DPA compiler rather than the host one",
    )
    ap.add_argument(
        "--decode-all-enums",
        action="store_true",
        help="emit a decoder for every enum in these headers, not only those a wrapped parameter "
        "carries. Engine and DPA ops usually arrive in a task or a struct, so parameter-typed "
        "decoding names a fraction of them.",
    )
    ap.add_argument(
        "--decode-enum",
        action="append",
        default=[],
        help="emit a decoder for this named enum even when no parameter carries its type; the "
        "value often arrives in a command buffer or a queue entry instead",
    )
    args = ap.parse_args()
    out = open(args.output, "w") if args.output else sys.stdout
    skip = set(filter(None, args.skip_classes.split(",")))

    def _p(*a):
        print(*a, file=out)


    # Text-extracted constant tables need no header parse; enum decoders still do.
    needs_clang = not args.only_decoders or bool(args.decode_enum) or args.decode_all_enums
    if needs_clang and not args.libclang:
        ap.error("--libclang is required unless --only-decoders is used without --decode-enum")

    cls_of = {}
    if not args.only_decoders:
        for line in Path(args.inventory).read_text().splitlines()[1:]:
            if line.strip():
                _, sym, cls = line.split("\t")
                cls_of[sym] = cls

    protos, parsed, all_enums, enum_src = {}, set(), {}, {}
    if needs_clang:
        _load_clang(args.libclang)
        for h in args.headers:
            got = prototypes(h, args.include, all_enums, enum_src)
            if got:
                parsed.add(h)
            protos.update(got)

    wrapped, skipped_variadic, unclassified = [], [], 0
    missing_cmd_tables = set()
    missing_field_layout = set()
    enums, flags = {}, {}
    # Decoders built from raw header text; their constants are kernel-only identifiers that the
    # compiled self-test cannot name.
    text_only = set()
    for spec in args.decode_constants:
        prefix, _, path = spec.partition("=")
        consts = constants_by_prefix(path, prefix)
        if consts:
            enums.setdefault(prefix, consts)
            text_only.add(prefix)
        else:
            print(f"// --decode-constants {spec}: nothing matched", file=sys.stderr)
    if args.decode_all_enums:
        for key, consts in all_enums.items():
            if consts:
                enums.setdefault(key, consts)
    for want in args.decode_enum:
        if want in all_enums:
            enums.setdefault(want, all_enums[want])
        else:
            print(f"// --decode-enum {want}: not found in these headers", file=sys.stderr)
    for sym, (ret, params, variadic) in sorted(protos.items()):
        cls = cls_of.get(sym)
        if cls is None:
            unclassified += 1
            continue
        if cls in skip or sym in OVERRIDE:
            continue
        if variadic:
            skipped_variadic.append(sym)
            continue
        plist = ", ".join(d for d, _, _ in params) or "void"
        vargs = ", ".join(n for _, n, _ in params)
        parts = []
        for _, n, ct in params:
            k = arg_kind(ct)
            if k == "skip":
                continue
            fields = FIELD_ARGS.get((sym, n))
            if fields:
                emitted = False
                for fname, dec in fields:
                    layout = field_layout(ct, fname)
                    if layout is None:
                        missing_field_layout.add(f"{sym}.{n}.{fname}")
                        continue
                    off, width = layout
                    parts.append(f"DC_A_FIELD({n}, {off}, {width}, {fname}, {dec})")
                    emitted = True
                if emitted:
                    continue
            cmd = CMD_ARGS.get((sym, n))
            if cmd:
                if cmd[1] in enums:
                    parts.append(f"DC_A_CMD({n}, {cmd[0]}, {cmd[1]})")
                    continue
                # Without the table the command buffer records as a bare pointer, naming no
                # command.
                missing_cmd_tables.add(cmd[1])
            fam = FLAG_ARGS.get((sym, n))
            if fam and fam in all_enums:
                flags[fam] = all_enums[fam]
                parts.append(f"DC_A_FLAGS({n}, {fam})")
                continue
            consts = enum_constants(ct)
            if consts:
                # --decode-all-enums keys by the bare spelling, enum_key by the canonical one.
                # Reuse the existing key rather than emitting the same decoder twice.
                bare = ct.get_canonical().spelling.replace("enum ", "").strip()
                key = bare if bare in enums else enum_key(ct)
                enums[key] = consts
                parts.append(f"DC_A_ENUM({n}, {key})")
            else:
                parts.append(f"DC_A_{k.upper()}({n})")
        kinds = " ".join(parts)
        # A void return needs a different wrapper body, flagged here so the consumer need not
        # reparse the type.
        wrapped.append((sym, cls, ret, plist, vargs, kinds, ret.strip() == "void"))

    if args.selftest_device:
        # Device headers (DPA, PCC) never reach the host self-test. A value assertion needs no
        # runtime: if the compiler that can parse the header disagrees, the file does not build.
        want = {k: v for k, v in enums.items()
                if k not in text_only and enum_src.get(k) and enum_src[k] not in parsed}
        for h in sorted({enum_src[k] for k in want}):
            _p(f'#include "{h}"')
        _p("")
        for key in sorted(want):
            first = {}
            for name, val in want[key]:
                first.setdefault(val, name)
            for name, val in want[key]:
                if first[val] == name:
                    _p(f'_Static_assert({name} == {val}, "{key}: {name} moved");')
        _p("")
        _p("int main(void) { return 0; }")
        if out is not sys.stdout:
            out.close()
        return
    _p("// Generated by gen_gotcha.py. Do not edit by hand.")
    # Recorded so the shim can compare these header versions against the runtime library rather
    # than decoding to a plausible wrong name.
    for lib, ver in sorted(built_against(args.headers, args.include).items()):
        _p(f'#define DC_BUILT_AGAINST_{lib.upper()} "{ver}"')
    # Spelled relative to the include directory it was found under, so a header in a subdirectory
    # (infiniband/verbs.h) is named the way a compiler will find it.
    inc_dirs = sorted({*args.include, "/usr/include"}, key=len, reverse=True)

    def inc_spelling(path):
        hp = Path(path)
        for d in inc_dirs:
            try:
                return str(hp.relative_to(Path(d)))
            except ValueError:
                continue
        return hp.name

    wrap_includes = sorted({inc_spelling(h) for h in args.headers if h in parsed})
    # Buffered as well as written: the per-library lists need the same prelude, emitted once into
    # its own header so there is one definition.
    prelude: list[str] = []
    _orig_p = _p

    def _p(line=""):  # noqa: F811 - shadows deliberately for the prelude section
        prelude.append(line)
        _orig_p(line)

    for h in wrap_includes:
        _p(f"#include <{h}>")
    # The flag decoders call std::snprintf, so the header carries its own dependency.
    _p("#include <cstdio>")
    _p("")
    # An ordinal in a trace is unreadable, so the record carries the enum's own constant name. An op
    # arriving in a command buffer has no parameter to type it, so its decoder is requested by name:
    # the DevX opcodes are the case that matters, 192 values in the kernel's mlx5_ifc.h.
    for key, consts in sorted(enums.items()):
        _p(f"inline const char* dc_enum_{key}(long long v) {{")
        _p("  switch (v) {")
        seen = set()
        for name, val in consts:
            if val in seen:
                continue
            seen.add(val)
            _p(f'    case {val}: return "{name}";')
        _p("    default: return nullptr;")
        _p("  }")
        _p("}")
    for key, consts in sorted(flags.items()):
        _p(f"inline int dc_flags_{key}(long long v, char* out, int cap) {{")
        _p("  int n = 0;")
        for name, val in consts:
            if val > 0:
                _p(f'  if ((v & {val}) == {val} && n < cap) '
                   f'n += std::snprintf(out + n, cap - n, "%s{name}", n ? "|" : "");')
        _p("  return n;")
        _p("}")
    for f in sorted(missing_field_layout):
        print(f"// FIELD_ARGS names {f}, which these headers do not lay out; the op stays a pointer",
              file=sys.stderr)
    for t in sorted(missing_cmd_tables):
        print(
            f"// CMD_ARGS wants the {t} table; pass --decode-constants {t}=<header> or the command "
            "buffer records as an undecoded pointer",
            file=sys.stderr,
        )
    if args.selftest:
        # The compiler resolves each constant from the header while the decoder answers from the
        # generated table, so a misread value shows up as a name mismatch, not a wrong label.
        _p("")
        _p("#include <cstring>")
        _p("static int g_checks = 0, g_fails = 0;")
        _p("static void ck(const char* got, const char* want, const char* where) {")
        _p("  ++g_checks;")
        _p("  if (got == nullptr || std::strcmp(got, want) != 0) {")
        _p("    ++g_fails;")
        _p('    std::printf("FAIL %s: got %s want %s\\n", where, got ? got : "(null)", want);')
        _p("  }")
        _p("}")
        _p("static void ckf(int n, const char* buf, const char* want, const char* where) {")
        _p("  ++g_checks;")
        _p("  if (n <= 0 || std::strstr(buf, want) == nullptr) {")
        _p("    ++g_fails;")
        _p('    std::printf("FAIL %s: got %s want to contain %s\\n", where, n > 0 ? buf : "(empty)", want);')
        _p("  }")
        _p("}")
        _p("int main() {")
        _p("  char b[512];")
        skipped_hdr = set()
        for key, consts in sorted(enums.items()):
            if key in text_only:
                continue
            # A device-side header does not compile for the host, so its names cannot be referenced
            # here. Reported, not silently dropped.
            src = enum_src.get(key)
            if src is not None and src not in parsed:
                skipped_hdr.add(key)
                continue
            first = {}
            for name, val in consts:
                first.setdefault(val, name)
            for name, val in consts:
                # An aliased value decodes to whichever name the table kept; asserting the alias
                # would fail on a correct table.
                _p(f'  ck(dc_enum_{key}({name}), "{first[val]}", "{key}/{name}");')
        for key, consts in sorted(flags.items()):
            for name, val in consts:
                if val > 0:
                    _p(f"  {{ const int n = dc_flags_{key}({name}, b, sizeof(b));")
                    _p(f'    ckf(n, b, "{name}", "{key}/{name}"); }}')
        for key in sorted(skipped_hdr):
            print(
                f"// selftest skips {key}: {Path(enum_src[key]).name} does not compile for the "
                "host, so its constants cannot be named here",
                file=sys.stderr,
            )
        _p('  std::printf("checks=%d fails=%d\\n", g_checks, g_fails);')
        _p("  return g_fails ? 1 : 0;")
        _p("}")
        if out is not sys.stdout:
            out.close()
        return
    if args.only_decoders:
        if out is not sys.stdout:
            out.close()
        return
    _p = _orig_p  # decoders end here; the list itself is per library

    if args.split_dir:
        shared = Path(args.split_dir) / "api_decoders.h"
        shared.parent.mkdir(parents=True, exist_ok=True)
        with open(shared, "w") as fh:
            print("// Generated by gen_gotcha.py. Do not edit by hand.", file=fh)
            print("// Vendor headers and the enum decoders, shared by every per-library wrap list.",
                  file=fh)
            print("#ifndef DATACRUMBS_UTILS_CLIENT_API_DECODERS_H", file=fh)
            print("#define DATACRUMBS_UTILS_CLIENT_API_DECODERS_H", file=fh)
            for line in prelude:
                print(line, file=fh)
            print("#endif", file=fh)

    _p("")
    _p("// X(name, class, ret, (params), (forward args), arg records, returns_void)")
    _p("// Arg records expand inside the wrapper body: DC_A_INT is a value worth reading,")
    _p("// DC_A_PTR an identity to join on. Anything needing a layout to interpret is omitted.")
    def _entry(rec):
        sym, cls, ret, plist, vargs, kinds, is_void = rec
        return (
            f"  X({sym}, {cls}, {ret}, ({plist}), ({vargs}), "
            f"{kinds or '/* no args */'}, {1 if is_void else 0}) \\"
        )

    _p("#define DC_WRAPPED_FUNCS(X) \\")
    for rec in wrapped:
        _p(_entry(rec))
    _p()

    # One list per library, split on the symbol prefix, so a TU that wraps DOCA never sees ibverbs.
    if args.split_dir:
        groups = {"doca": "doca_", "ibverbs": "ibv_", "mlx5": "mlx5dv_", "flexio": "flexio_",
                  "pka": "pka_"}
        claimed = set()
        written = []
        for lib, prefix in groups.items():
            rows = [r for r in wrapped if r[0].startswith(prefix)]
            claimed.update(r[0] for r in rows)
            written.append((lib, rows))
        # Whatever matches no prefix still has to go somewhere or the split would quietly drop it.
        written.append(("other", [r for r in wrapped if r[0] not in claimed]))
        total = 0
        for lib, rows in written:
            d = Path(args.split_dir) / lib
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "api.h", "w") as fh:
                print("// Generated by gen_gotcha.py. Do not edit by hand.", file=fh)
                print(f"// The {lib} wrap list. X(name, class, ret, (params), (forward args),", file=fh)
                print("// arg records, returns_void)", file=fh)
                # The entries name vendor types and call the decoders, so each file pulls the
                # shared prelude: without it the macro compiles but the wrappers it expands into
                # do not.
                print('#include "datacrumbs/utils/client/api_decoders.h"', file=fh)
                print(file=fh)
                # Named per library so one TU can take several lists without colliding.
                print(f"#define DC_WRAPPED_FUNCS_{lib.upper()}(X) \\", file=fh)
                for rec in rows:
                    print(_entry(rec), file=fh)
                print(file=fh)
                print(f"// {len(rows)} wrapped", file=fh)
            total += len(rows)
        assert total == len(wrapped), f"split lost symbols: {total} != {len(wrapped)}"
        print(f"// split {total} symbols across {len(written)} libraries", file=sys.stderr)
    _p(f"// {len(wrapped)} wrapped")
    if skipped_variadic:
        _p(f"// {len(skipped_variadic)} variadic, not wrappable: {', '.join(skipped_variadic)}")
    # Emitted from the same pass that skipped them, so the two lists cannot drift.
    if args.tramp_out:
        with open(args.tramp_out, "w") as t:
            print("// Generated by gen_gotcha.py. Do not edit by hand.", file=t)
            print("// T(name, class)", file=t)
            print("#define DC_TRAMP_FUNCS(T) \\", file=t)
            for sym in sorted(skipped_variadic):
                print(f"  T({sym}, {cls_of.get(sym, 'other')}) \\", file=t)
            print(file=t)
            print(f"// {len(skipped_variadic)} variadic symbols", file=t)
    if unclassified:
        _p(f"// {unclassified} declared in the headers but absent from the inventory")


if __name__ == "__main__":
    main()
