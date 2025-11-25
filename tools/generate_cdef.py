#!/usr/bin/env python3
"""
Generate cardano-c.cdef from ALL libcardano-c headers.

Fixes:
- RESTORES TYPE SAFETY (Removes the void* hack).
- Auto-generates Forward Declarations for ALL structs.
  (Solves dependencies: Callback can use Struct* before Struct is fully defined).
- Strict 5-layer sorting.
"""

from pathlib import Path
import re
import sys

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIR = ROOT / "vendor" / "cardano-c" / "lib" / "include" / "cardano"
CDEF_PATH = ROOT / "src" / "biglup" / "cometa" / "_cdef" / "cardano-c.cdef"

PRIMITIVES = """\
typedef _Bool              bool;
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned int       uint32_t;
typedef signed int         int32_t;
typedef unsigned long long uint64_t;
typedef long long          int64_t;
typedef unsigned char      byte_t;
typedef int                cardano_error_t;
"""

ATTRIBUTE_MACROS = [
    "CARDANO_EXPORT",
    "CARDANO_NODISCARD",
]


# ------------------------------------------------------------------------------
# 1. TEXT CLEANING
# ------------------------------------------------------------------------------

def strip_comments(text: str) -> str:
    text = re.sub(r'//.*', '', text)
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
    return text


def strip_preprocessor(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def strip_scaffolding(text: str) -> str:
    text = re.sub(r'extern\s+"C"\s*\{', ' ', text)
    for macro in ATTRIBUTE_MACROS:
        text = text.replace(macro, "")
    return text


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


# ------------------------------------------------------------------------------
# 2. PARSING
# ------------------------------------------------------------------------------

def extract_statements(text: str) -> list[str]:
    """Parse C code by counting braces."""
    clean_text = normalize_whitespace(text)
    statements = []
    current_stmt = []
    depth = 0

    for char in clean_text:
        current_stmt.append(char)
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth < 0:
                depth = 0
                current_stmt = []
                continue
        elif char == ';':
            if depth == 0:
                stmt_str = "".join(current_stmt).strip()
                if stmt_str and stmt_str != ";":
                    statements.append(stmt_str)
                current_stmt = []
    return statements


# ------------------------------------------------------------------------------
# 3. TYPE MANIPULATION
# ------------------------------------------------------------------------------

def get_defined_primitives():
    defined = set()
    for line in PRIMITIVES.splitlines():
        parts = line.strip().split()
        if not parts: continue
        name = parts[-1].rstrip(";")
        defined.add(name)
    return defined


ALREADY_DEFINED = get_defined_primitives()


def is_duplicate(stmt: str) -> bool:
    if not stmt.startswith("typedef "): return False
    if "(*" in stmt: return False
    parts = stmt.rstrip(";").split()
    name = parts[-1]
    if "]" in name: name = name.split("[")[0]
    return name in ALREADY_DEFINED


def extract_struct_name(stmt: str) -> str:
    """
    Extracts 'foo_t' from 'typedef struct { ... } foo_t;'
    or 'typedef struct foo foo_t;'
    """
    if "typedef struct" not in stmt:
        return None
    parts = stmt.rstrip(";").split()
    name = parts[-1]
    # Simple validation to ensure it's a valid identifier
    if re.match(r'^[A-Za-z0-9_]+$', name):
        return name
    return None


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

def main():
    if not INCLUDE_DIR.exists():
        sys.exit(f"Error: Header directory not found: {INCLUDE_DIR}")

    headers = sorted(INCLUDE_DIR.rglob("*.h"))
    print(f"Processing {len(headers)} headers...")

    full_blob = ""
    for h in headers:
        full_blob += h.read_text(encoding="utf-8") + "\n"

    # 1. Clean
    processed = strip_comments(full_blob)
    processed = strip_preprocessor(processed)
    processed = strip_scaffolding(processed)

    # 2. Extract
    statements = extract_statements(processed)

    # 3. Categorize & Auto-Generate Forward Declarations
    enum_stmts = []
    alias_stmts = []
    callback_stmts = []
    struct_def_stmts = []
    func_stmts = []

    # Track aliases we have already added to avoid duplicates
    existing_aliases = set()

    for stmt in statements:
        if is_duplicate(stmt): continue

        if stmt.startswith("typedef"):
            if "typedef enum" in stmt:
                enum_stmts.append(stmt)
            elif "(*" in stmt:
                callback_stmts.append(stmt)
            elif "{" in stmt and "struct" in stmt:
                # This is a full struct definition.
                # We MUST ensure a forward declaration exists for it.
                struct_name = extract_struct_name(stmt)
                if struct_name and struct_name not in existing_aliases:
                    # Inject "typedef struct Name Name;"
                    forward_decl = f"typedef struct {struct_name} {struct_name};"
                    alias_stmts.append(forward_decl)
                    existing_aliases.add(struct_name)

                struct_def_stmts.append(stmt)
            else:
                # Existing Alias / Forward Decl
                # E.g. "typedef struct foo foo_t;"
                struct_name = extract_struct_name(stmt)
                if struct_name:
                    if struct_name not in existing_aliases:
                        alias_stmts.append(stmt)
                        existing_aliases.add(struct_name)
                else:
                    # Simple typedef (e.g. typedef uint64_t coin_t;)
                    alias_stmts.append(stmt)
        else:
            func_stmts.append(stmt)

    # 4. Output Construction
    # ORDER: Enums -> Aliases (Forward Decls) -> Callbacks -> Struct Bodies -> Functions

    final_lines = [PRIMITIVES, "\n/* ---- Generated Declarations ---- */\n"]

    final_lines.append("\n/* -- Enums -- */")
    final_lines.extend(enum_stmts)

    final_lines.append("\n/* -- Aliases & Forward Decls -- */")
    final_lines.extend(alias_stmts)

    final_lines.append("\n/* -- Callbacks -- */")
    final_lines.extend(callback_stmts)

    final_lines.append("\n/* -- Struct Definitions -- */")
    final_lines.extend(struct_def_stmts)

    final_lines.append("\n/* -- Functions -- */")
    final_lines.extend(func_stmts)

    final_text = "\n".join(final_lines) + "\n"

    CDEF_PATH.parent.mkdir(parents=True, exist_ok=True)
    CDEF_PATH.write_text(final_text, encoding="utf-8")

    print(f"Success! Wrote to: {CDEF_PATH}")
    print(f"Stats:")
    print(f"  - Aliases/Forward Decls: {len(alias_stmts)}")
    print(f"  - Callbacks: {len(callback_stmts)}")
    print(f"  - Struct Definitions: {len(struct_def_stmts)}")


if __name__ == "__main__":
    main()